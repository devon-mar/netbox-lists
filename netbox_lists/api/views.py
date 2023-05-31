import itertools
import operator
from functools import reduce
from typing import Any, Dict, Iterable, List, Optional, Union

from dcim.filtersets import DeviceFilterSet
from dcim.models import Device
from django.conf import settings
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import (
    extend_schema,
    extend_schema_view,
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
)
from extras.models import Tag
from ipam.filtersets import (
    AggregateFilterSet,
    IPAddressFilterSet,
    IPRangeFilterSet,
    ServiceFilterSet,
)
from ipam.models import Aggregate, IPAddress, IPRange, Prefix, Service
from netaddr import IPNetwork
from rest_framework import mixins, status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.routers import APIRootView
from rest_framework.viewsets import GenericViewSet
from virtualization.filtersets import VirtualMachineFilterSet
from virtualization.models import VirtualMachine

from .constants import AS_CIDR_PARAM_NAME, FAMILY_PARAM_NAME, SUMMARIZE_PARAM_NAME
from .filtersets import CustomPrefixFilterSet
from .renderers import PlainTextRenderer
from .serializers import (
    PrometheusDeviceSerializer,
    PrometheusIPAddressSerializer,
    PrometheusVMSerializer,
)
from .utils import (
    device_vm_primary_list,
    filter_queryset,
    get_as_cidr_param,
    get_attr_json,
    get_family_param,
    get_service_ips,
    get_summarize_param,
    get_svc_primary_ips_param,
    iprange_to_cidrs,
    make_ip_list_response,
    set_prefixlen_max,
)

FAMILY_PARAM = OpenApiParameter(
    name=FAMILY_PARAM_NAME,
    location="query",
    description="Filter IPs and or prefixes by address family.",
    type=int,
    enum=(4, 6),
)
AS_CIDR_PARAM = OpenApiParameter(
    name=AS_CIDR_PARAM_NAME,
    location="query",
    description="Return IPs as /32 or /128",
    default=settings.PLUGINS_CONFIG["netbox_lists"]["as_cidr"],
    type=bool,
)
SUMMARIZE_PARAM = OpenApiParameter(
    name=SUMMARIZE_PARAM_NAME,
    location="query",
    description="Summarize the IPs/prefixes before returning them.",
    type=bool,
    default=settings.PLUGINS_CONFIG["netbox_lists"]["summarize"],
)

PROMETHEUS_RESPONSE_SCHEMA = OpenApiResponse(
    response={
        "type": "object",
        "properties": {
            "targets": {
                "type": "array",
                "items": {"type": "string", "description": "Primary IP or name"},
            },
            "labels": {"type": "object", "additionalProperties": {"type": "string"}},
        },
    },
    examples=[
        OpenApiExample(
            "Device",
            value={
                "targets": ["2001:db8::1"],
                "labels": {
                    "__meta_netbox_id": "1",
                    "__meta_netbox_name": "dmi01-akron-rtr01",
                    "__meta_netbox_status": "active",
                    "__meta_netbox_site_name": "DM-Akron",
                    "__meta_netbox_platform_name": "Cisco IOS",
                    "__meta_netbox_primary_ip": "2001:db8::1",
                    "__meta_netbox_primary_ip4": "",
                    "__meta_netbox_primary_ip6": "2001:db8::1",
                    "__meta_netbox_serial": "",
                },
            },
        ),
        OpenApiExample(
            "VM",
            value={
                "targets": ["192.0.2.100"],
                "labels": {
                    "__meta_netbox_id": "361",
                    "__meta_netbox_name": "vm1",
                    "__meta_netbox_status": "active",
                    "__meta_netbox_cluster_name": "DO-AMS3",
                    "__meta_netbox_site_name": "",
                    "__meta_netbox_role_name": "Application Server",
                    "__meta_netbox_platform_name": "Ubuntu Linux 20.04",
                    "__meta_netbox_primary_ip": "192.0.2.100",
                    "__meta_netbox_primary_ip4": "192.0.2.100",
                    "__meta_netbox_primary_ip6": "",
                },
            },
        ),
    ],
)

OTHER_PARAMS = {
    FAMILY_PARAM_NAME,
    AS_CIDR_PARAM_NAME,
    SUMMARIZE_PARAM_NAME,
    # for BrowsableAPIRenderer
    "format",
}

LISTS_RESPONSES = {
    (200, "application/json"): OpenApiResponse(
        description="JSON or plain text list of IP addresses/prefixes.",
        response=str,
        examples=[
            OpenApiExample("JSON example", value=["192.0.2.0/24", "2001:db8::/64"]),
        ],
    ),
    (200, "text/plain"): OpenApiResponse(
        response=str,
        # This description is not used in swagger.
        examples=[OpenApiExample("Text example", value="192.0.2.0/24\n2001:db8::/64")],
    ),
}


class ListsRootView(APIRootView):
    def get_view_name(self):
        return "Lists"


class InvalidFilterCheckMixin:
    # Adapted from
    # https://stackoverflow.com/questions/27182527/how-can-i-stop-django-rest-framework-to-show-all-records-if-query-parameter-is-w
    def get_queryset(self):
        other_params = getattr(self, "other_query_params", OTHER_PARAMS)
        qs = super().get_queryset()
        invalid_filters = set(self.request.query_params).difference(
            other_params, self.filterset_class.get_filters()
        )

        if len(invalid_filters) > 0:
            raise ValidationError({k: "Invalid filter." for k in invalid_filters})

        return qs


# View set instead of APIView sknce it makes OpenApi filtersets work.
class ListsBaseViewSet(GenericViewSet):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer, PlainTextRenderer]
    pagination_class = None
    filter_backends = (DjangoFilterBackend,)  # disable ordering

    # Adapted from
    # https://github.com/netbox-community/netbox/blob/a33e47780b42f49f4ea536bace1617fa7dda31ab/
    # netbox/netbox/api/views.py#L179
    def initial(self, request: Request, *args, **kwargs):
        super().initial(request, *args, **kwargs)

        if not request.user.is_authenticated:
            return

        # Restrict the view's QuerySet to allow only the permitted objects
        self.queryset = self.queryset.restrict(request.user, "view")


class ValuesListViewSet(InvalidFilterCheckMixin, ListsBaseViewSet):
    @extend_schema(parameters=[SUMMARIZE_PARAM], responses=LISTS_RESPONSES)
    def list(self, request: Request, use_net_ip: bool = False) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        return make_ip_list_response(
            queryset, get_summarize_param(request), use_net_ip=use_net_ip
        )


@extend_schema_view(list=extend_schema(description="Get a list of prefixes."))
class PrefixListViewSet(ValuesListViewSet):
    queryset = Prefix.objects.values_list("prefix", flat=True).distinct()
    filterset_class = CustomPrefixFilterSet


@extend_schema_view(list=extend_schema(description="Get a list of aggregate prefixes."))
class AggregateListViewSet(ValuesListViewSet):
    queryset = Aggregate.objects.values_list("prefix", flat=True).distinct()
    filterset_class = AggregateFilterSet


class IPAddressListViewSet(InvalidFilterCheckMixin, ListsBaseViewSet):
    queryset = IPAddress.objects.values_list("address", flat=True).distinct()
    filterset_class = IPAddressFilterSet

    @extend_schema(
        description="Get a list of IP addresses.",
        parameters=[AS_CIDR_PARAM, SUMMARIZE_PARAM],
        responses=LISTS_RESPONSES,
    )
    def list(self, request: Request) -> Response:
        queryset = self.filter_queryset(self.get_queryset())
        return make_ip_list_response(
            (set_prefixlen_max(i) for i in queryset),
            get_summarize_param(request),
            use_net_ip=not get_as_cidr_param(request),
        )


class ServiceListviewSet(InvalidFilterCheckMixin, ListsBaseViewSet):
    queryset = Service.objects.all()
    filterset_class = ServiceFilterSet
    other_query_params = OTHER_PARAMS.union({"primary_ips"})

    @extend_schema(
        description="Get a list of IPs associated with services.",
        parameters=[
            FAMILY_PARAM,
            AS_CIDR_PARAM,
            SUMMARIZE_PARAM,
            OpenApiParameter(
                name="primary_ips",
                location="query",
                description="Return Primary IPs if the service doesn't have any assigned IPs.",
                type=bool,
                default=settings.PLUGINS_CONFIG["netbox_lists"]["service_primary_ips"],
            ),
        ],
        responses=LISTS_RESPONSES,
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


class DevicesListViewSet(InvalidFilterCheckMixin, ListsBaseViewSet):
    queryset = Device.objects.all()
    filterset_class = DeviceFilterSet

    @extend_schema(
        description="Get the primary IPs of devices.",
        parameters=[AS_CIDR_PARAM, FAMILY_PARAM, SUMMARIZE_PARAM],
        responses=LISTS_RESPONSES,
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


class VirtualMachinesListViewSet(InvalidFilterCheckMixin, ListsBaseViewSet):
    queryset = VirtualMachine.objects.all()
    filterset_class = VirtualMachineFilterSet

    @extend_schema(
        description="Get the primary IPs of virtual machines.",
        parameters=[AS_CIDR_PARAM, FAMILY_PARAM, SUMMARIZE_PARAM],
        responses=LISTS_RESPONSES,
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


class DevicesVMsListViewSet(ListsBaseViewSet):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer, PlainTextRenderer]
    # We need to have `queryset defined`. Otherwise, the following occurs:
    # Cannot apply TokenPermissions on a view that does not set `.queryset` or have a `.get_queryset()` method.
    # See https://github.com/encode/django-rest-framework/blob/
    # 71e6c30034a1dd35a39ca74f86c371713e762c79/rest_framework/permissions.py#L207
    #
    # Therefore, we use Device as the model.
    queryset = Device.objects.all()
    filterset_class = DeviceFilterSet

    def validate_filters(self):
        valid_filters = OTHER_PARAMS.union(
            set(DeviceFilterSet.get_filters()).intersection(
                VirtualMachineFilterSet.get_filters()
            )
        )

        invalid_filters = set(self.request.query_params).difference(valid_filters)
        if len(invalid_filters) > 0:
            raise ValidationError({k: "Invalid filter." for k in invalid_filters})

    @extend_schema(
        description="Combined devices and virtual machines primary IPs list. "
        "Use only filters common to both devices and VMs.",
        parameters=[AS_CIDR_PARAM, FAMILY_PARAM, SUMMARIZE_PARAM],
        responses=LISTS_RESPONSES,
    )
    def list(self, request: Request) -> Response:
        self.validate_filters()

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


class IPRangeListViewSet(InvalidFilterCheckMixin, ListsBaseViewSet):
    queryset = IPRange.objects.all()
    filterset_class = IPRangeFilterSet

    @extend_schema(
        description="Get a list of CIDRs for each range.",
        parameters=[SUMMARIZE_PARAM],
        responses=LISTS_RESPONSES,
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
    ) -> Iterable[IPNetwork]:
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

    def check_query(self) -> None:
        """Raises an exception if an invalid query param is used."""
        valid_params = {
            SUMMARIZE_PARAM_NAME,
            FAMILY_PARAM_NAME,
            "prefixes",
            "aggregates",
            "services",
            "devices",
            "vms",
            "devices_primary",
            "vms_primary",
            "ips",
            "service_primary_ips",
            "all",
            "all_primary",
            # for BrowsableAPIRenderer
            "format",
        }

        invalid_params = set(self.request.query_params).difference(valid_params)
        if len(invalid_params) > 0:
            raise ValidationError({k: "Invalid filter." for k in invalid_params})

    @extend_schema(
        description="Get a list of IPs/prefixes associated with the tag.",
        parameters=[
            SUMMARIZE_PARAM,
            FAMILY_PARAM,
            OpenApiParameter(
                name="prefixes",
                location="query",
                description="Include prefixes.",
                type=bool,
                default=False,
            ),
            OpenApiParameter(
                name="aggregates",
                location="query",
                description="Include aggregates.",
                type=bool,
                default=False,
            ),
            OpenApiParameter(
                name="services",
                location="query",
                description="Include services.",
                type=bool,
                default=False,
            ),
            OpenApiParameter(
                name="devices",
                location="query",
                description="Include devices. Mutually exclusive with `devices_primary`.",
                type=bool,
                default=False,
            ),
            OpenApiParameter(
                name="vms",
                location="query",
                description="Include VMs. Mutually exclusive with `vms_primary`.",
                type=bool,
                default=False,
            ),
            OpenApiParameter(
                name="devices_primary",
                location="query",
                description="Include devices (primary IPs only). Mutually exclusive with `devices`.",
                type=bool,
                default=False,
            ),
            OpenApiParameter(
                name="vms_primary",
                location="query",
                description="Include VMs (primary IPs only). Mutually exclusive with `vms`.",
                type=bool,
                default=False,
            ),
            OpenApiParameter(
                name="ips",
                location="query",
                description="Include IP Addresses.",
                type=bool,
                default=False,
            ),
            OpenApiParameter(
                name="service_primary_ips",
                location="query",
                description="Return primary IPs if the service doesn't have any assigned IPs. "
                "Only used if `services=True`.",
                type=bool,
                default=settings.PLUGINS_CONFIG["netbox_lists"]["service_primary_ips"],
            ),
            OpenApiParameter(
                name="all",
                location="query",
                description="Include **all** options except *_primary.",
                type=bool,
                default=False,
            ),
            OpenApiParameter(
                name="all_primary",
                location="query",
                description="Include **all** options, using device/VM primary IPs.",
                type=bool,
                default=False,
            ),
        ],
        responses=LISTS_RESPONSES,
    )
    def retrieve(self, request: Request, slug: Optional[str] = None) -> Response:
        if not slug:
            return Response("No slug", status.HTTP_400_BAD_REQUEST)

        self.check_query()

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


class PrometheusDeviceSD(
    InvalidFilterCheckMixin, mixins.ListModelMixin, ListsBaseViewSet
):
    queryset = Device.objects.all()
    filterset_class = DeviceFilterSet
    serializer_class = PrometheusDeviceSerializer


class PrometheusVirtualMachineSD(
    InvalidFilterCheckMixin, mixins.ListModelMixin, ListsBaseViewSet
):
    queryset = VirtualMachine.objects.filter()
    filterset_class = VirtualMachineFilterSet
    serializer_class = PrometheusVMSerializer


class PrometheusIPAddressSD(
    InvalidFilterCheckMixin, mixins.ListModelMixin, ListsBaseViewSet
):
    queryset = IPAddress.objects.filter()
    filterset_class = IPAddressFilterSet
    serializer_class = PrometheusIPAddressSerializer


class DevicesVMsAttrsListViewSet(ListsBaseViewSet):
    renderer_classes = [JSONRenderer, BrowsableAPIRenderer]
    filterset_class = DeviceFilterSet
    filter_backends = (DjangoFilterBackend,)
    queryset = Device.objects.filter()

    def _to_dict(
        self,
        attrs: Iterable[Iterable[str]],
        display_attrs: Iterable[Iterable[str]],
        device: Union[Device, VirtualMachine],
    ) -> Dict[str, Any]:
        """Convert a device or VM to a dictionary"""
        return {
            "__".join(d_a): get_attr_json(a, device)
            for a, d_a in zip(attrs, display_attrs)
        }

    def validate_filters(self):
        valid_filters = set(DeviceFilterSet.get_filters()).intersection(
            VirtualMachineFilterSet.get_filters()
        )

        invalid_filters = set(self.request.query_params).difference(valid_filters)
        if len(invalid_filters) > 0:
            raise ValidationError({k: "Invalid filter." for k in invalid_filters})

    @extend_schema(
        description="Get a list of device and VM objects. "
        "Use only filters common to both devices and VMs.",
        responses={
            200: OpenApiResponse(
                response={
                    "type": "array",
                    "items": {"type": "object", "additionalProperties": True},
                },
                examples=[
                    OpenApiExample(
                        "Example 1",
                        value={
                            "id": 1,
                            "name": "dmi01-akron-rtr01",
                            "role__slug": "router",
                            "platform__slug": "cisco-ios",
                            "primary_ip__address": "2001:db8::1/64",
                            "tags": [],
                        },
                    )
                ],
            )
        },
    )
    def list(self, request: Request) -> Response:
        self.validate_filters()

        attrs = settings.PLUGINS_CONFIG["netbox_lists"]["devices_vms_attrs"]

        device_attrs: List[Iterable[str]] = []
        for a in attrs:
            if len(a) > 0 and a[0] == "role":
                device_attrs.append(("device_role", *a[1:]))
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
