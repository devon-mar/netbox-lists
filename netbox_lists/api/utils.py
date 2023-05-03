import itertools
from typing import Any, Iterable, List, Union

from django.conf import settings
from django.db.models import Q
from django.db.models.query import QuerySet
from django_filters import FilterSet
from django_filters.utils import translate_validation
from netaddr import cidr_merge, IPNetwork, iprange_to_cidrs
from rest_framework.exceptions import ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from taggit.managers import _TaggableManager

from .constants import AS_CIDR_PARAM_NAME, FAMILY_PARAM_NAME, SUMMARIZE_PARAM_NAME


def make_ip_list_response(
    networks: Iterable[IPNetwork],
    summarize: bool,
    use_net_ip: bool = False,
) -> Response:
    ret: Iterable[str]
    if summarize is True:
        if use_net_ip is True:
            ret = (str(i) for i in cidr_merge([network.ip for network in networks]))
        else:
            ret = (str(i) for i in cidr_merge([str(i) for i in networks]))
    elif use_net_ip is True:
        ret = set(str(i.ip) for i in networks)
    else:
        ret = set(str(i) for i in networks)

    return Response(ret)


def set_prefixlen_max(ipn: IPNetwork) -> IPNetwork:
    ipn.prefixlen = 32 if ipn.version == 4 else 128
    return ipn


def device_vm_primary_list(
    qs: QuerySet[Any], family: Union[int, None]
) -> Iterable[IPNetwork]:
    if family is None:
        queryset = qs.filter(
            Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False)
        )
        retindex = -1
    elif family == 4:
        queryset = qs.filter(primary_ip4__isnull=False)
        retindex = 0
    else:
        queryset = qs.filter(primary_ip6__isnull=False)
        retindex = 1

    queryset = queryset.values_list("primary_ip4__address", "primary_ip6__address")

    if retindex >= 0:
        return (set_prefixlen_max(i[retindex]) for i in queryset)
    else:
        return (
            set_prefixlen_max(i) for i in itertools.chain.from_iterable(queryset) if i
        )


def services_primary_ips(
    qs: QuerySet[Any], family: Union[int, None]
) -> Iterable[IPNetwork]:
    family_filter = Q()
    values: List[str] = []
    if family == 4 or family is None:
        family_filter |= Q(device__primary_ip4__isnull=False) | Q(
            virtual_machine__primary_ip4__isnull=False
        )
        values.extend(
            [
                "device__primary_ip4__address",
                "virtual_machine__primary_ip4__address",
            ]
        )
    if family == 6 or family is None:
        family_filter |= Q(device__primary_ip6__isnull=False) | Q(
            virtual_machine__primary_ip6__isnull=False
        )
        values.extend(
            [
                "device__primary_ip6__address",
                "virtual_machine__primary_ip6__address",
            ]
        )

    qs = qs.filter(Q(ipaddresses__isnull=True), family_filter).values_list(*values)
    return (set_prefixlen_max(i) for i in itertools.chain.from_iterable(qs) if i)


def services_assigned_ips(
    qs: QuerySet[Any], family: Union[int, None]
) -> Iterable[IPNetwork]:
    if family is None:
        family_filter = Q()
    elif family == 4:
        family_filter = Q(ipaddresses__address__family=4)
    else:
        family_filter = Q(ipaddresses__address__family=6)

    return (
        qs.filter(Q(ipaddresses__isnull=False), family_filter)
        .values_list("ipaddresses__address", flat=True)
        .distinct()
    )


def get_service_ips(
    qs: QuerySet[Any], family: Union[int, None], include_primaries: bool
) -> Iterable[IPNetwork]:
    iterables: List[Iterable[IPNetwork]] = [services_assigned_ips(qs, family)]

    if include_primaries is True:
        iterables.append(services_primary_ips(qs, family))

    return (set_prefixlen_max(i) for i in itertools.chain.from_iterable(iterables))


def get_svc_primary_ips_param(param: str, req: Request) -> bool:
    val = req.query_params.get(param, None)
    if val is None:
        return settings.PLUGINS_CONFIG["netbox_lists"]["service_primary_ips"]
    elif val.lower() == "true":
        return True
    elif val.lower() == "false":
        return False
    else:
        raise ValidationError(f"{param} must be true or false.")


def get_family_param(req: Request) -> Union[int, None]:
    """
    Raises a ValidationError if family is not '4' or '6'.
    """
    val = req.query_params.get(FAMILY_PARAM_NAME, None)

    if val is not None and val not in ["4", "6"]:
        raise ValidationError("Family must be 4 or 6.")
    elif val is None:
        return None
    else:
        return int(val)


def get_as_cidr_param(req: Request) -> bool:
    val = req.query_params.get(AS_CIDR_PARAM_NAME, None)
    if val is None:
        return settings.PLUGINS_CONFIG["netbox_lists"].get("as_cidr", True)
    elif val.lower() == "true":
        return True
    elif val.lower() == "false":
        return False
    else:
        raise ValidationError("as_cidr must be true or false.")


def get_summarize_param(req: Request) -> bool:
    val = req.query_params.get(SUMMARIZE_PARAM_NAME, None)
    if val is None:
        return settings.PLUGINS_CONFIG["netbox_lists"].get("summarize", True)
    elif val.lower() == "true":
        return True
    elif val.lower() == "false":
        return False
    else:
        raise ValidationError("summarize must be true or false.")


def ip_range_prefixes(start: IPNetwork, end: IPNetwork) -> List[IPNetwork]:
    return iprange_to_cidrs(start.ip, end.ip)


def _json_rep(obj: Any) -> Union[str, int, bool, list, dict, None]:
    """Return a JSON serializable representation"""
    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    elif isinstance(obj, list):
        return [_json_rep(o) for o in obj]
    elif isinstance(obj, dict):
        return {str(k): _json_rep(v) for k, v in obj.items()}
    elif isinstance(obj, _TaggableManager):
        return list(obj.slugs())
    else:
        return str(obj)


def get_attr(attrs: Iterable[str], obj: Any) -> Any:
    for a in attrs:
        if obj is None:
            return None
        elif isinstance(obj, dict):
            obj = obj.get(a)
        else:
            obj = getattr(obj, a, None)
    return obj


def get_attr_str(attrs: Iterable[str], obj: Any) -> str:
    val = get_attr(attrs, obj)
    if val is None:
        return ""
    return str(val)


def get_attr_json(attrs: Iterable[str], obj: Any) -> Any:
    return _json_rep(get_attr(attrs, obj))


def filter_queryset(filterset: FilterSet) -> QuerySet:
    if not filterset.is_valid():
        raise translate_validation(filterset.errors)
    return filterset.qs
