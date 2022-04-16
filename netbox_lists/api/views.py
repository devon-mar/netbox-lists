import itertools
import operator
from functools import reduce
from typing import Any, Dict, Iterable, List, Union

import netaddr
from dcim.filtersets import DeviceFilterSet
from dcim.models import Device
from django.conf import settings
from django.db.models import Q
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from extras.models import Tag
from ipam.filtersets import (
    AggregateFilterSet,
    IPAddressFilterSet,
    IPRangeFilterSet,
    ServiceFilterSet,
)
from ipam.models import Aggregate, IPAddress, IPRange, Prefix, Service
from netaddr import IPNetwork
from rest_framework import status
from rest_framework.generics import get_object_or_404
from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.routers import APIRootView
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from virtualization.filtersets import VirtualMachineFilterSet
from virtualization.models import VirtualMachine

from .constants import AS_CIDR_PARAM_NAME, FAMILY_PARAM_NAME, SUMMARIZE_PARAM_NAME
from .filtersets import CustomPrefixFilterSet
from .renderers import PlainTextRenderer
from .utils import (
    device_vm_primary_list,
    get_as_cidr_param,
    get_attr_r,
    get_family_param,
    get_service_ips,
    get_summarize_param,
    get_svc_primary_ips_param,
    iprange_to_cidrs,
    make_ip_list_response,
    set_prefixlen_max,
    filter_queryset,
)

FAMILY_PARAM = openapi.Parameter(
    FAMILY_PARAM_NAME,
    in_=openapi.IN_QUERY,
    description="Filter IPs and or prefixes by address family (4|6).",
    type=openapi.TYPE_INTEGER,
    enum=[4, 6],
)
AS_CIDR_PARAM = openapi.Parameter(
    AS_CIDR_PARAM_NAME,
    in_=openapi.IN_QUERY,
    description="Return IPs as /32 or /128",
    type=openapi.TYPE_BOOLEAN,
)
SUMMARIZE_PARAM = openapi.Parameter(
    SUMMARIZE_PARAM_NAME,
    in_=openapi.IN_QUERY,
    description="Summarize the IPs/Prefixes before returning them.",
    type=openapi.TYPE_BOOLEAN,
)


class ListsRootView(APIRootView):
    def get_view_name(self):
        return "Lists"


class ListsBaseViewSet(GenericViewSet):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer, PlainTextRenderer]

    # Adapted from
    # https://github.com/netbox-community/netbox/blob/a33e47780b42f49f4ea536bace1617fa7dda31ab/
    # netbox/netbox/api/views.py#L179
    def initial(self, request: Request, *args, **kwargs):
        super().initial(request, *args, **kwargs)

        if not request.user.is_authenticated:
            return

        # Restrict the view's QuerySet to allow only the permitted objects
        self.queryset = self.queryset.restrict(request.user, "view")


class ValuesListViewSet(ListsBaseViewSet):
    @swagger_auto_schema(manual_parameters=[SUMMARIZE_PARAM])
    def list(self, request: Request, use_net_ip: bool = False) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        return make_ip_list_response(
            queryset, get_summarize_param(request), use_net_ip=use_net_ip
        )


class PrefixListViewSet(ValuesListViewSet):
    queryset = Prefix.objects.values_list("prefix", flat=True).distinct()
    filterset_class = CustomPrefixFilterSet


class AggregateListViewSet(ValuesListViewSet):
    queryset = Aggregate.objects.values_list("prefix", flat=True).distinct()
    filterset_class = AggregateFilterSet


class IPAddressListViewSet(ListsBaseViewSet):
    queryset = IPAddress.objects.values_list("address", flat=True).distinct()
    filterset_class = IPAddressFilterSet

    @swagger_auto_schema(manual_parameters=[AS_CIDR_PARAM])
    def list(self, request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        return make_ip_list_response(
            (set_prefixlen_max(i) for i in queryset),
            get_summarize_param(request),
            use_net_ip=not get_as_cidr_param(request),
        )


class ServiceListviewSet(ListsBaseViewSet):
    queryset = Service.objects.all()
    filterset_class = ServiceFilterSet

    @swagger_auto_schema(
        manual_parameters=[
            AS_CIDR_PARAM,
            SUMMARIZE_PARAM,
            openapi.Parameter(
                "primary_ips",
                in_=openapi.IN_QUERY,
                description="Return Primary IPs if the service doesn't have any assigned IPs.",
                type=openapi.TYPE_BOOLEAN,
            ),
        ]
    )
    def list(self, request: Request) -> Response:
        as_cidr = get_as_cidr_param(request)
        family = get_family_param(request)
        summarize = get_summarize_param(request)
        primary_ips = get_svc_primary_ips_param("primary_ips", request)

        qs = self.filter_queryset(self.get_queryset())
        return make_ip_list_response(
            get_service_ips(qs, family, primary_ips),
            summarize,
            use_net_ip=not as_cidr,
        )


class DevicesListViewSet(ListsBaseViewSet):
    queryset = Device.objects.all()
    filterset_class = DeviceFilterSet

    @swagger_auto_schema(
        operation_description="Returns the primary IPs of devices.",
        manual_parameters=[AS_CIDR_PARAM, FAMILY_PARAM, SUMMARIZE_PARAM],
    )
    def list(self, request: Request) -> Response:
        family = get_family_param(request)
        as_cidr = get_as_cidr_param(request)
        summarize = get_summarize_param(request)

        return make_ip_list_response(
            device_vm_primary_list(
                self.filter_queryset((self.get_queryset())),
                family,
            ),
            summarize,
            use_net_ip=not as_cidr,
        )


class VirtualMachinesListViewSet(ListsBaseViewSet):
    queryset = VirtualMachine.objects.all()
    filterset_class = VirtualMachineFilterSet

    @swagger_auto_schema(
        operation_description="Returns the primary IPs of virtual machines.",
        manual_parameters=[AS_CIDR_PARAM, FAMILY_PARAM],
    )
    def list(self, request: Request) -> Response:
        family = get_family_param(request)
        as_cidr = get_as_cidr_param(request)
        summarize = get_summarize_param(request)

        return make_ip_list_response(
            device_vm_primary_list(
                self.filter_queryset((self.get_queryset())),
                family,
            ),
            summarize,
            use_net_ip=not as_cidr,
        )


class DevicesVMsListView(APIView):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer, PlainTextRenderer]
    # We need to have `queryset defined`. Otherwise, the following occurs:
    # Cannot apply TokenPermissions on a view that does not set `.queryset` or have a `.get_queryset()` method.
    # See https://github.com/encode/django-rest-framework/blob/
    # 71e6c30034a1dd35a39ca74f86c371713e762c79/rest_framework/permissions.py#L207
    #
    # Therefore, we use Device as the model.
    queryset = Device.objects.all()

    @swagger_auto_schema(
        operation_description="Combined devices and virtual machines primary IPs list. "
        "Use only parameters common to both devices and VMs ('role' can be used for both devices and VMs).",
        manual_parameters=[SUMMARIZE_PARAM],
    )
    def get(self, request: Request) -> Response:
        family = get_family_param(request)
        as_cidr = get_as_cidr_param(request)
        summarize = get_summarize_param(request)

        devices_qs = filter_queryset(
            DeviceFilterSet(
                request.query_params,
                queryset=Device.objects.restrict(request.user, "view").all(),
            )
        )
        vms_qs = filter_queryset(
            VirtualMachineFilterSet(
                request.query_params,
                queryset=VirtualMachine.objects.restrict(request.user, "view").all(),
            )
        )
        devices = device_vm_primary_list(devices_qs, family)
        vms = device_vm_primary_list(vms_qs, family)
        return make_ip_list_response(
            itertools.chain(devices, vms), summarize, use_net_ip=not as_cidr
        )


class IPRangeListViewSet(ListsBaseViewSet):
    queryset = IPRange.objects.all()
    filterset_class = IPRangeFilterSet

    @swagger_auto_schema(
        operation_description="Returns a list of CIDRs for each range.",
        manual_parameters=[SUMMARIZE_PARAM],
    )
    def list(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        return make_ip_list_response(
            itertools.chain.from_iterable(
                iprange_to_cidrs(r.start_address.ip, r.end_address.ip) for r in queryset
            ),
            get_summarize_param(request),
        )


class TagsListViewSet(ListsBaseViewSet):
    queryset = Tag.objects.all()
    lookup_field = "slug"
    lookup_value_regex = r"[-\w]+"

    def param_all_any(self, request: Request, param: str) -> bool:
        return (
            param in request.query_params
            or "all" in request.query_params
            or "all_primary" in request.query_params
        )

    def param_all_primary(self, request: Request, param: str, primary: bool) -> bool:
        return (
            param in request.query_params
            or ("all" in request.query_params and not primary)
            or ("all_primary" in request.query_params and primary)
        )

    def get_prefixes(
        self, tag: Tag, family: Union[int, None], request: Request
    ) -> Iterable[IPNetwork]:
        if not self.param_all_any(request, "prefixes"):
            return []

        if family == 4:
            family_filter = Q(prefix__family=4)
        elif family == 6:
            family_filter = Q(prefix__family=6)
        else:
            family_filter = Q()
        return (
            Prefix.objects.restrict(request.user, "view")
            .filter(Q(tags=tag) & family_filter)
            .values_list("prefix", flat=True)
            .distinct()
        )

    def get_aggregates(
        self, tag: Tag, family: Union[int, None], request: Request
    ) -> Iterable[IPNetwork]:
        if not self.param_all_any(request, "aggregates"):
            return []

        if family == 4:
            family_filter = Q(prefix__family=4)
        elif family == 6:
            family_filter = Q(prefix__family=6)
        else:
            family_filter = Q()

        return (
            Aggregate.objects.restrict(request.user, "view")
            .filter(Q(tags=tag) & family_filter)
            .values_list("prefix", flat=True)
            .distinct()
        )

    def get_ips(
        self, tag: Tag, family: Union[int, None], request: Request
    ) -> Iterable[netaddr.IPNetwork]:
        if family == 4:
            family_filter = Q(address__family=4)
        elif family == 6:
            family_filter = Q(address__family=6)
        else:
            family_filter = Q()

        ip_filters = []
        if self.param_all_any(request, "ips"):
            ip_filters.append(Q(tags=tag))
        if self.param_all_primary(request, "devices", False):
            ip_filters.append(Q(interface__device__tags=tag))
        if self.param_all_primary(request, "vms", False):
            ip_filters.append(Q(vminterface__virtual_machine__tags=tag))

        if len(ip_filters) > 0:
            return (
                set_prefixlen_max(i)
                for i in IPAddress.objects.restrict(request.user, "view")
                .filter(reduce(operator.or_, ip_filters) & family_filter)
                .values_list("address", flat=True)
                .distinct()
            )
        else:
            return []

    def get_services(
        self, tag: Tag, family: Union[int, None], request: Request
    ) -> Iterable[IPNetwork]:
        if not self.param_all_any(request, "services"):
            return []

        return get_service_ips(
            Service.objects.restrict(request.user, "view").filter(tags=tag),
            family,
            get_svc_primary_ips_param("service_primary_ips", request),
        )

    def get_devices_primary(
        self, tag: Tag, family: Union[int, None], request: Request
    ) -> Iterable[IPNetwork]:
        if not self.param_all_primary(request, "devices_primary", True):
            return []

        return device_vm_primary_list(
            Device.objects.restrict(request.user, "view").filter(tags=tag), family
        )

    def get_vms_primary(
        self, tag: Tag, family: Union[int, None], request: Request
    ) -> Iterable[IPNetwork]:
        if not self.param_all_primary(request, "vms_primary", True):
            return []

        return device_vm_primary_list(
            VirtualMachine.objects.restrict(request.user, "view").filter(tags=tag),
            family,
        )

    @swagger_auto_schema(
        manual_parameters=[
            SUMMARIZE_PARAM,
            openapi.Parameter(
                "prefixes",
                in_=openapi.IN_QUERY,
                description="Include prefixes",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "aggregates",
                in_=openapi.IN_QUERY,
                description="Include aggregates",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "services",
                in_=openapi.IN_QUERY,
                description="Include services",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "devices",
                in_=openapi.IN_QUERY,
                description="Include devices",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "vms",
                in_=openapi.IN_QUERY,
                description="Include vms",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "devices_primary",
                in_=openapi.IN_QUERY,
                description="Include devices (primary IPs only)",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "vms_primary",
                in_=openapi.IN_QUERY,
                description="Include vms (primary IPs only)",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "ips",
                in_=openapi.IN_QUERY,
                description="Include IP Addresses",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "service_primary_ips",
                in_=openapi.IN_QUERY,
                description="Return Primary IPs if the service doesn't have any assigned IPs.",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "all",
                in_=openapi.IN_QUERY,
                description="Include ALL of the above options except *_primary.",
                type=openapi.TYPE_BOOLEAN,
            ),
            openapi.Parameter(
                "all_primary",
                in_=openapi.IN_QUERY,
                description="Include ALL of the above options, using Device/VM primary IPs.",
                type=openapi.TYPE_BOOLEAN,
            ),
        ]
    )
    def retrieve(self, request, slug=None) -> Response:
        if not slug:
            return Response("No slug", status.HTTP_400_BAD_REQUEST)

        tag = get_object_or_404(Tag, slug=slug)
        family = get_family_param(request)

        prefixes = self.get_prefixes(tag, family, request)
        aggregates = self.get_aggregates(tag, family, request)
        ips = self.get_ips(tag, family, request)
        services = self.get_services(tag, family, request)
        devices_primary = self.get_devices_primary(tag, family, request)
        vms_primary = self.get_vms_primary(tag, family, request)

        return make_ip_list_response(
            itertools.chain(
                prefixes, aggregates, ips, services, devices_primary, vms_primary
            ),
            get_summarize_param(request),
        )


class PrometheusDeviceSD(GenericViewSet):
    queryset = Device.objects.all()
    filterset_class = DeviceFilterSet

    def _sd_device(self, d: Device) -> Dict[str, Any]:
        labels = {
            "__meta_netbox_id": d.id,
            "__meta_netbox_name": d.name,
            "__meta_netbox_status": d.status,
            "__meta_netbox_site_name": d.site.name,
            "__meta_netbox_platform_name": d.platform.name if d.platform else "",
            "__meta_netbox_primary_ip": str(d.primary_ip.address.ip)
            if d.primary_ip
            else "",
            "__meta_netbox_primary_ip4": str(d.primary_ip4.address.ip)
            if d.primary_ip4
            else "",
            "__meta_netbox_primary_ip6": str(d.primary_ip6.address.ip)
            if d.primary_ip6
            else "",
            "__meta_netbox_serial": d.serial,
        }
        for k, v in d.custom_field_data.items():
            labels[f"__meta_netbox_cf_{k}"] = v

        return {
            "targets": [str(d.primary_ip.address.ip) if d.primary_ip else d.name],
            "labels": labels,
        }

    def list(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        return Response([self._sd_device(d) for d in queryset])


class PrometheusVirtualMachineSD(GenericViewSet):
    queryset = VirtualMachine.objects.filter()
    filterset_class = VirtualMachineFilterSet

    def _sd_vm(self, vm: VirtualMachine) -> Dict[str, Any]:
        labels = {
            "__meta_netbox_id": str(vm.id),
            "__meta_netbox_name": vm.name,
            "__meta_netbox_status": vm.status,
            "__meta_netbox_cluster_name": vm.cluster.name,
            "__meta_netbox_site_name": vm.site.name if vm.site else "",
            "__meta_netbox_role_name": vm.role.name if vm.role else "",
            "__meta_netbox_platform_name": vm.platform.name if vm.platform else "",
            "__meta_netbox_primary_ip": str(vm.primary_ip.address.ip)
            if vm.primary_ip
            else "",
            "__meta_netbox_primary_ip4": str(vm.primary_ip4.address.ip)
            if vm.primary_ip4
            else "",
            "__meta_netbox_primary_ip6": str(vm.primary_ip6.address.ip)
            if vm.primary_ip6
            else "",
        }
        for k, v in vm.custom_field_data.items():
            labels[f"__meta_netbox_cf_{k}"] = str(v)

        return {
            "targets": [str(vm.primary_ip.address.ip) if vm.primary_ip else vm.name],
            "labels": labels,
        }

    def list(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        return Response([self._sd_vm(vm) for vm in queryset])


class DevicesVMsAttrsListView(APIView):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer]
    queryset = Device.objects.all()

    def _to_dict(
        self,
        attrs: List[str],
        display_attrs: List[str],
        device: Union[Device, VirtualMachine],
    ) -> Dict[str, Any]:
        """Convert a device or VM to a dictionary"""
        return {d_a: get_attr_r(a, device) for a, d_a in zip(attrs, display_attrs)}

    def get(self, request: Request) -> Response:
        attrs = settings.PLUGINS_CONFIG["netbox_lists"]["devices_vms_attrs"]

        device_attrs = []
        for a in attrs:
            if a == "role":
                device_attrs.append("role")
            elif a.startswith("role__"):
                device_attrs.append(a.replace("role__", "device_role__"))
            else:
                device_attrs.append(a)

        devices = filter_queryset(
            DeviceFilterSet(
                request.query_params,
                queryset=Device.objects.restrict(request.user, "view").all(),
            )
        )
        vms = filter_queryset(
            VirtualMachineFilterSet(
                request.query_params,
                queryset=VirtualMachine.objects.restrict(request.user, "view").all(),
            )
        )
        return Response(
            [self._to_dict(attrs, attrs, d) for d in vms]
            + [self._to_dict(device_attrs, attrs, d) for d in devices]
        )
