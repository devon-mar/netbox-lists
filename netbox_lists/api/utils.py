from typing import List, Union
from django.db.models import Q
from django.db.models.query import QuerySet
from rest_framework.exceptions import ValidationError
from netaddr import IPNetwork


def as_cidr(ipn: IPNetwork) -> str:
    return str(ipn.ip) + "/32" if ipn.version == 4 else str(ipn.ip) + "/128"


def devicesVmPrimaryList(qs: QuerySet, family: Union[str, None], cidr: bool = False) -> List[str]:
    if family is None:
        queryset = qs.filter(Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False))
        retindex = -1
    elif family == '4':
        queryset = qs.filter(primary_ip4__isnull=False)
        retindex = 0
    else:
        queryset = qs.filter(primary_ip6__isnull=False)
        retindex = 1

    queryset = queryset.values_list("primary_ip4__address", "primary_ip6__address")

    if retindex >= 0 and cidr is True:
        return list(set([as_cidr(tpl[retindex]) for tpl in queryset]))
    elif retindex >= 0:
        return list(set([str(tpl[retindex].ip) for tpl in queryset]))
    elif cidr is True:
        return list(set([as_cidr(adr) for tupl in queryset for adr in tupl if adr]))
    else:
        return list(set([str(adr.ip) for tupl in queryset for adr in tupl if adr]))


def validateFamilyParam(family: Union[str, None]):
    """
    Raises a ValidationError if family is not '4' or '6'.
    """
    if family is not None and family not in ['4', '6']:
        raise ValidationError("Family must be 4 or 6.")
