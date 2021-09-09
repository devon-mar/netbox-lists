from netbox_lists.api.filtersets import CustomPrefixFilterSet
import operator
from functools import reduce
from typing import List, Union

from django.db.models import Q
from rest_framework import status
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.routers import APIRootView
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from rest_framework.renderers import JSONRenderer, BrowsableAPIRenderer
from rest_framework.request import Request

from ipam.models import Prefix, Aggregate, IPAddress, Service
from ipam.filtersets import IPAddressFilterSet, AggregateFilterSet, ServiceFilterSet
from dcim.models import Device
from dcim.filtersets import DeviceFilterSet
from virtualization.models import VirtualMachine
from virtualization.filtersets import VirtualMachineFilterSet
from extras.models import Tag

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from .renderers import PlainTextRenderer
from .utils import (
    device_vm_primary_list, format_ipn, get_as_cidr,
    get_family_param, get_service_ips, get_svc_primary_ips_param, make_response
)
from .constants import FAMILY_PARAM_NAME, AS_CIDR_PARAM_NAME


FAMILY_PARAM = openapi.Parameter(
    FAMILY_PARAM_NAME,
    in_=openapi.IN_QUERY,
    description="Filter IPs and or prefixes by address family (4|6).",
    type=openapi.TYPE_INTEGER,
    enum=[4, 6]
)
AS_CIDR_PARAM = openapi.Parameter(
    AS_CIDR_PARAM_NAME, in_=openapi.IN_QUERY,
    description="Return IPs as /32 or /128", type=openapi.TYPE_BOOLEAN
)


class ListsRootView(APIRootView):
    def get_view_name(self):
        return "Lists"


class ListsBaseViewSet(GenericViewSet):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer, PlainTextRenderer]


class ValuesListViewSet(ListsBaseViewSet):

    def list(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())

        return Response([str(i) for i in queryset])


class PrefixListViewSet(ValuesListViewSet):
    queryset = Prefix.objects.values_list("prefix", flat=True).distinct()
    filterset_class = CustomPrefixFilterSet


class AggregateListViewSet(ValuesListViewSet):
    queryset = Aggregate.objects.values_list("prefix", flat=True).distinct()
    filterset_class = AggregateFilterSet


class IPAddressListViewSet(ValuesListViewSet):
    queryset = IPAddress.objects.values_list("address", flat=True).distinct()
    filterset_class = IPAddressFilterSet

    @swagger_auto_schema(manual_parameters=[AS_CIDR_PARAM])
    def list(self, request):
        queryset = self.filter_queryset(self.get_queryset())

        return make_response([format_ipn(i, get_as_cidr(request)) for i in queryset])


class ServiceListviewSet(ValuesListViewSet):
    queryset = Service.objects.all()

    filterset_class = ServiceFilterSet

    @swagger_auto_schema(manual_parameters=[
        AS_CIDR_PARAM,
        openapi.Parameter(
            "primary_ips", in_=openapi.IN_QUERY,
            description="Return Primary IPs if the service doesn't have any assigned IPs.", type=openapi.TYPE_BOOLEAN
        )
    ])
    def list(self, request: Request) -> Response:
        as_cidr = get_as_cidr(request)
        family = get_family_param(request)
        primary_ips = get_svc_primary_ips_param("primary_ips", request)

        qs = self.filter_queryset(self.get_queryset())
        return make_response(get_service_ips(qs, as_cidr, family, primary_ips))


class DevicesListViewSet(ValuesListViewSet):
    queryset = Device.objects.all()
    filterset_class = DeviceFilterSet

    @ swagger_auto_schema(
        operation_description="Returns the primary IPs of devices.",
        manual_parameters=[AS_CIDR_PARAM, FAMILY_PARAM]
    )
    def list(self, request: Request) -> Response:

        family = get_family_param(request)

        return Response(device_vm_primary_list(
            self.filter_queryset((self.get_queryset())),
            family,
            cidr=get_as_cidr(request)
        ))


class VirtualMachinesListViewSet(ValuesListViewSet):
    queryset = VirtualMachine.objects.all()
    filterset_class = VirtualMachineFilterSet

    @ swagger_auto_schema(
        operation_description="Returns the primary IPs of virtual machines.",
        manual_parameters=[AS_CIDR_PARAM, FAMILY_PARAM]
    )
    def list(self, request: Request) -> Response:
        family = get_family_param(request)

        return Response(device_vm_primary_list(
            self.filter_queryset((self.get_queryset())),
            family,
            cidr=get_as_cidr(request)
        ))


class DevicesVMsListView(APIView):
    queryset = Device.objects.all()

    @ swagger_auto_schema(
        operation_description="Combined devices and virtual machines primary IPs list. "
        "Use only parameters common to both devices and VMs."
    )
    def get(self, request: Request) -> Response:
        family = get_family_param(request)
        as_cidr = get_as_cidr(request)
        devices_fs = DeviceFilterSet(request.query_params, queryset=Device.objects.all())
        vms_fs = VirtualMachineFilterSet(request.query_params, queryset=VirtualMachine.objects.all())
        devices = device_vm_primary_list(devices_fs.qs, family, as_cidr)
        vms = device_vm_primary_list(vms_fs.qs, family, as_cidr)
        return make_response(devices + vms)


class TagsListViewSet(ListsBaseViewSet):
    queryset = Tag.objects.all()
    lookup_field = "slug"
    lookup_value_regex = r"[-\w]+"

    def get_prefixes(self, tag: Tag, family: Union[int, None], request: Request) -> List[str]:
        if "prefixes" not in request.query_params:
            return []

        if family == 4:
            family_filter = Q(prefix__family=4)
        elif family == 6:
            family_filter = Q(prefix__family=6)
        else:
            family_filter = Q()
        qs = Prefix.objects.filter(Q(tags=tag) & family_filter).values_list("prefix", flat=True).distinct()
        return [str(i) for i in qs]

    def get_aggregates(self, tag: Tag, family: Union[int, None], request: Request) -> List[str]:
        if "aggregates" not in request.query_params:
            return []

        if family == 4:
            family_filter = Q(prefix__family=4)
        elif family == 6:
            family_filter = Q(prefix__family=6)
        else:
            family_filter = Q()

        qs = Aggregate.objects.filter(Q(tags=tag) & family_filter).values_list("prefix", flat=True).distinct()
        return [str(i) for i in qs]

    def get_ips(self, tag: Tag, family: Union[int, None], request: Request) -> List[str]:
        if family == 4:
            family_filter = Q(address__family=4)
        elif family == 6:
            family_filter = Q(address__family=6)
        else:
            family_filter = Q()

        ip_filters = []
        if "ips" in request.query_params:
            ip_filters.append(Q(tags=tag))
        if "devices" in request.query_params:
            ip_filters.append(Q(interface__device__tags=tag))
        if "vms" in request.query_params:
            ip_filters.append(Q(vminterface__virtual_machine__tags=tag))

        if len(ip_filters) > 0:
            return [
                format_ipn(i, True)
                for i in IPAddress.objects.filter(
                    reduce(operator.or_, ip_filters) & family_filter
                ).values_list("address", flat=True).distinct()
            ]
        else:
            return []

    def get_services(self, tag: Tag, family: Union[int, None], request: Request) -> List[str]:
        if "services" not in request.query_params:
            return []

        return get_service_ips(
            Service.objects.filter(tags=tag),
            True,
            family,
            get_svc_primary_ips_param("service_primary_ips", request)
        )

    def get_devices_primary(self, tag: Tag, family: Union[int, None], request) -> List[str]:
        if "devices_primary" not in request.query_params:
            return []

        return device_vm_primary_list(
            Device.objects.filter(tags=tag),
            family,
            cidr=True
        )

    def get_vms_primary(self, tag: Tag, family: Union[int, None], request) -> List[str]:
        if "vms_primary" not in request.query_params:
            return []

        return device_vm_primary_list(
            VirtualMachine.objects.filter(tags=tag),
            family,
            cidr=True
        )

    @ swagger_auto_schema(manual_parameters=[
        openapi.Parameter(
            "prefixes", in_=openapi.IN_QUERY,
            description="Include prefixes", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            "aggregates", in_=openapi.IN_QUERY,
            description="Include aggregates", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            "services", in_=openapi.IN_QUERY,
            description="Include services", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            "devices", in_=openapi.IN_QUERY,
            description="Include devices", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            "vms", in_=openapi.IN_QUERY,
            description="Include vms", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            "devices_primary", in_=openapi.IN_QUERY,
            description="Include devices (primary IPs only)", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            "vms_primary", in_=openapi.IN_QUERY,
            description="Include vms (primary IPs only)", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            "ips", in_=openapi.IN_QUERY,
            description="Include IP Addresses", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            "service_primary_ips", in_=openapi.IN_QUERY,
            description="Return Primary IPs if the service doesn't have any assigned IPs.", type=openapi.TYPE_BOOLEAN
        )
    ])
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

        return make_response(prefixes + aggregates + ips + services + devices_primary + vms_primary)


class PrometheusDeviceSD(GenericViewSet):
    queryset = Device.objects.all()
    filterset_class = DeviceFilterSet

    def _sd_device(self, d: Device) -> dict:
        labels = {
            "__meta_netbox_id": d.id,
            "__meta_netbox_name": d.name,
            "__meta_netbox_status": d.status,
            "__meta_netbox_site_name": d.site.name,
            "__meta_netbox_platform_name": d.platform.name if d.platform else "",
            "__meta_netbox_primary_ip": str(d.primary_ip.address.ip) if d.primary_ip else "",
            "__meta_netbox_primary_ip4": str(d.primary_ip4.address.ip) if d.primary_ip4 else "",
            "__meta_netbox_primary_ip6": str(d.primary_ip6.address.ip) if d.primary_ip6 else "",
            "__meta_netbox_serial": d.serial
        }
        for k, v in d.custom_field_data.items():
            labels[f"__meta_netbox_cf_{k}"] = v

        return {
            "targets": [str(d.primary_ip.address.ip) if d.primary_ip else d.name],
            "labels": labels
        }

    def list(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        return Response([self._sd_device(d) for d in queryset])


class PrometheusVirtualMachineSD(GenericViewSet):
    queryset = VirtualMachine.objects.filter()
    filterset_class = VirtualMachineFilterSet

    def _sd_vm(self, vm: VirtualMachine) -> dict:
        labels = {
            "__meta_netbox_id": vm.id,
            "__meta_netbox_name": vm.name,
            "__meta_netbox_status": vm.status,
            "__meta_netbox_cluster_name": vm.cluster.name,
            "__meta_netbox_site_name": vm.site.name if vm.site else "",
            "__meta_netbox_role_name": vm.role.name if vm.role else "",
            "__meta_netbox_platform_name": vm.platform.name if vm.platform else "",
            "__meta_netbox_primary_ip": str(vm.primary_ip.address.ip) if vm.primary_ip else "",
            "__meta_netbox_primary_ip4": str(vm.primary_ip4.address.ip) if vm.primary_ip4 else "",
            "__meta_netbox_primary_ip6": str(vm.primary_ip6.address.ip) if vm.primary_ip6 else ""
        }
        for k, v in vm.custom_field_data.items():
            labels[f"__meta_netbox_cf_{k}"] = v

        return {
            "targets": [str(vm.primary_ip.address.ip) if vm.primary_ip else vm.name],
            "labels": labels
        }

    def list(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        return Response([self._sd_vm(vm) for vm in queryset])
