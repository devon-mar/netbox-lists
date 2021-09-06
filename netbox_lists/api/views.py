import operator
from functools import reduce

from django.db.models import Q
from rest_framework import status
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.routers import APIRootView
from rest_framework.viewsets import GenericViewSet
from rest_framework.renderers import JSONRenderer, BrowsableAPIRenderer
from rest_framework.request import Request

from ipam.models import Prefix, Aggregate, IPAddress, Service
from ipam.filtersets import PrefixFilterSet, IPAddressFilterSet, AggregateFilterSet, ServiceFilterSet
from dcim.models import Device
from dcim.filtersets import DeviceFilterSet
from virtualization.models import VirtualMachine
from virtualization.filtersets import VirtualMachineFilterSet
from extras.models import Tag

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from .renderers import PlainTextRenderer
from .utils import as_cidr, devicesVmPrimaryList, validateFamilyParam


FAMILY_PARAM = openapi.Parameter(
    "family",
    in_=openapi.IN_QUERY,
    description="Filter IPs and or prefixes by address family (4|6).",
    type=openapi.TYPE_INTEGER,
    enum=[4, 6]
)
AS_CIDR_PARAM = openapi.Parameter(
    "as_cidr", in_=openapi.IN_QUERY,
    description="Return IPs as /32 or /128", type=openapi.TYPE_BOOLEAN
)


class ListsRootView(APIRootView):
    def get_view_name(self):
        return "Lists"


class ValuesListViewSet(GenericViewSet):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer, PlainTextRenderer]

    def list(self, request):
        queryset = self.filter_queryset(self.get_queryset())

        return Response([str(i) for i in queryset])


class PrefixListViewSet(ValuesListViewSet):
    queryset = Prefix.objects.values_list("prefix", flat=True).distinct()
    filterset_class = PrefixFilterSet


class AggregateListViewSet(ValuesListViewSet):
    queryset = Aggregate.objects.values_list("prefix", flat=True).distinct()
    filterset_class = AggregateFilterSet


class IPAddressListViewSet(ValuesListViewSet):
    queryset = IPAddress.objects.values_list("address", flat=True).distinct()
    filterset_class = IPAddressFilterSet

    @swagger_auto_schema(manual_parameters=[AS_CIDR_PARAM])
    def list(self, request):
        queryset = self.filter_queryset(self.get_queryset())

        if "as_cidr" in request.query_params:
            return Response(list(set([as_cidr(i) for i in queryset])))
        # We use list/set because distinct() won't work
        # for two IPs with the same address but different prefix length.
        return Response(list(set([str(i.ip) for i in queryset])))


class ServiceListviewSet(ValuesListViewSet):
    queryset = Service.objects.filter(ipaddresses__isnull=False).values_list(
        "ipaddresses__address", flat=True
    ).distinct()

    filterset_class = ServiceFilterSet

    @swagger_auto_schema(manual_parameters=[AS_CIDR_PARAM])
    def list(self, request):
        queryset = self.filter_queryset(self.get_queryset())

        if "as_cidr" in request.query_params:
            return Response(list(set([as_cidr(i) for i in queryset])))

        return Response(list(set([str(i.ip) for i in queryset])))


class DevicesListViewSet(ValuesListViewSet):
    queryset = Device.objects.all()
    filterset_class = DeviceFilterSet

    @swagger_auto_schema(
        operation_description="Returns the primary IPs of devices.",
        manual_parameters=[AS_CIDR_PARAM, FAMILY_PARAM]
    )
    def list(self, request: Request):

        family = request.query_params.get("family", None)
        validateFamilyParam(family)

        return Response(devicesVmPrimaryList(
            self.filter_queryset((self.get_queryset())),
            family,
            cidr=("as_cidr" in request.query_params)
        ))


@swagger_auto_schema(operation_description="Returns the primary IPs of devices.")
class VirtualMachinesListViewSet(ValuesListViewSet):
    queryset = VirtualMachine.objects.all()
    filterset_class = VirtualMachineFilterSet

    @swagger_auto_schema(
        operation_description="Returns the primary IPs of devices.",
        manual_parameters=[AS_CIDR_PARAM, FAMILY_PARAM]
    )
    def list(self, request: Request):
        family = request.query_params.get("family", None)
        validateFamilyParam(family)

        return Response(devicesVmPrimaryList(
            self.filter_queryset((self.get_queryset())),
            family,
            cidr=("as_cidr" in request.query_params)
        ))


class TagsListViewSet(GenericViewSet):
    queryset = Tag.objects.all()
    lookup_field = "slug"
    lookup_value_regex = r"[-\w]+"
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer, PlainTextRenderer]

    @swagger_auto_schema(manual_parameters=[
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
        )
    ])
    def retrieve(self, request, slug=None):
        if not slug:
            return Response("No slug", status.HTTP_400_BAD_REQUEST)

        tag = get_object_or_404(Tag, slug=slug)

        family = request.query_params.get("family", None)
        validateFamilyParam(family)

        if family == '4':
            family_filter = Q(family=4)
        elif family == '6':
            family_filter = Q(family=6)
        else:
            family_filter = Q()

        if "prefixes" in request.query_params:
            prefixes = [
                str(i) for i in Prefix.objects.filter(tags=tag).values_list("prefix", flat=True).distinct()
            ]
        else:
            prefixes = []

        if "aggregates" in request.query_params:
            aggregates = [
                str(i) for i in Aggregate.objects.filter(tags=tag).values_list("prefix", flat=True).distinct()
            ]
        else:
            aggregates = []

        ip_filters = []
        if "ips" in request.query_params:
            ip_filters.append(Q(tags=tag))
        if "devices" in request.query_params:
            ip_filters.append(Q(interface__device__tags=tag))
        if "vms" in request.query_params:
            ip_filters.append(Q(vminterface__virtual_machine__tags=tag))
        if len(ip_filters) > 0:
            ips = [
                as_cidr(i)
                for i in IPAddress.objects.filter(
                    reduce(operator.or_, ip_filters) & family_filter
                ).values_list("address", flat=True).distinct()
            ]
        else:
            ips = []

        if "services" in request.query_params:
            if family == ' 4':
                svc_family_filter = Q(ipaddresses__address__family=4)
            elif family == '6':
                svc_family_filter = Q(ipaddresses__address__family=6)
            else:
                svc_family_filter = Q()

            services = [
                as_cidr(i)
                for i in Service.objects.filter(
                    Q(ipaddresses__isnull=False) & Q(tags=tag) & svc_family_filter
                ).values_list("ipaddresses__address", flat=True).distinct()
            ]
        else:
            services = []

        if "devices_primary" in request.query_params:
            devices_primary = devicesVmPrimaryList(
                Device.objects.filter(tags=tag),
                family,
                cidr=True
            )
        else:
            devices_primary = []

        if "vms_primary" in request.query_params:
            vms_primary = devicesVmPrimaryList(
                VirtualMachine.objects.filter(tags=tag),
                family,
                cidr=True
            )
        else:
            vms_primary = []

        return Response(list(set(prefixes + aggregates + ips + services + devices_primary + vms_primary)))


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

    def list(self, request):
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

    def list(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        return Response([self._sd_vm(vm) for vm in queryset])
