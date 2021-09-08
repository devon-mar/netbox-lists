from typing import List, Union, Any
from django.db.models import Q
from django.db.models.query import QuerySet
from rest_framework.request import Request
from django.conf import settings
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from netaddr import IPNetwork
from .constants import FAMILY_PARAM_NAME, AS_CIDR_PARAM_NAME


def make_response(ips: List[str]) -> Response:
    return Response(list(set(ips)))


def format_ipn(ipn: IPNetwork, as_cidr: bool) -> str:
    if as_cidr:
        return str(ipn.ip) + "/32" if ipn.version == 4 else str(ipn.ip) + "/128"
    else:
        return str(ipn.ip)


def device_vm_primary_list(qs: QuerySet[Any], family: Union[int, None], cidr: bool = False) -> List[str]:
    if family is None:
        queryset = qs.filter(Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False))
        retindex = -1
    elif family == 4:
        queryset = qs.filter(primary_ip4__isnull=False)
        retindex = 0
    else:
        queryset = qs.filter(primary_ip6__isnull=False)
        retindex = 1

    queryset = queryset.values_list("primary_ip4__address", "primary_ip6__address")

    if retindex >= 0:
        return list(set([format_ipn(tpl[retindex], cidr) for tpl in queryset]))
    else:
        return list(set([format_ipn(adr, cidr) for tupl in queryset for adr in tupl if adr]))


def services_primary_ips(qs: QuerySet[Any], as_cidr: bool, family: Union[int, None]) -> List[str]:
    values = []
    if family is None:
        family_filter = Q(
            Q(device__primary_ip4__isnull=False)
            | Q(device__primary_ip6__isnull=False)
            | Q(virtual_machine__primary_ip4__isnull=False)
            | Q(virtual_machine__primary_ip6__isnull=False)
        )
        values = [
            "device__primary_ip4__address", "device__primary_ip6__address",
            "virtual_machine__primary_ip4__address", "virtual_machine__primary_ip6__address"
        ]
    elif family == 4:
        family_filter = Q(Q(device__primary_ip4__isnull=False) | Q(virtual_machine__primary_ip4__isnull=False))
        values = ["device__primary_ip4__address", "virtual_machine__primary_ip4__address"]
    else:
        family_filter = Q(Q(device__primary_ip6__isnull=False) | Q(virtual_machine__primary_ip6__isnull=False))
        values = ["device__primary_ip6__address", "virtual_machine__primary_ip6__address"]

    qs = qs.filter(Q(ipaddresses__isnull=True), family_filter).values_list(*values)
    return list(set([format_ipn(adr, as_cidr) for tupl in qs for adr in tupl if adr]))


def services_assigned_ips(qs: QuerySet[Any], as_cidr: bool, family: Union[int, None]) -> List[str]:
    if family is None:
        family_filter = Q()
    elif family == 4:
        family_filter = Q(ipaddresses__address__family=4)
    else:
        family_filter = Q(ipaddresses__address__family=6)

    qs = qs.filter(
        Q(ipaddresses__isnull=False),
        family_filter
    ).values_list("ipaddresses__address", flat=True).distinct()

    return [format_ipn(i, as_cidr) for i in qs]


def get_service_ips(qs: QuerySet[Any], as_cidr: bool, family: Union[int, None], include_primaries: bool) -> List[str]:
    if include_primaries:
        return list(set(services_assigned_ips(qs, as_cidr, family) + services_primary_ips(qs, as_cidr, family)))

    return services_assigned_ips(qs, as_cidr, family)


def get_svc_primary_ips_param(param: str, req: Request) -> bool:
    val = req.query_params.get(param, None)
    if val is None:
        return settings.PLUGINS_CONFIG["netbox_lists"].get("service_primary_ips", True)
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

    if val is not None and val not in ['4', '6']:
        raise ValidationError("Family must be 4 or 6.")
    elif val is None:
        return None
    else:
        return int(val)


def get_as_cidr(req: Request) -> bool:
    val = req.query_params.get(AS_CIDR_PARAM_NAME, None)
    if val is None:
        return settings.PLUGINS_CONFIG["netbox_lists"].get("as_cidr", True)
    elif val.lower() == "true":
        return True
    elif val.lower() == "false":
        return False
    else:
        raise ValidationError("as_cidr must be true or false.")
