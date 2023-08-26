from rest_framework.routers import DefaultRouter

from .views import (
    AggregateListViewSet,
    DevicesListViewSet,
    DevicesVMsAttrsListViewSet,
    DevicesVMsListViewSet,
    IPAddressListViewSet,
    IPRangeListViewSet,
    ListsRootView,
    PrefixListViewSet,
    PrometheusDeviceSD,
    PrometheusIPAddressSD,
    PrometheusVirtualMachineSD,
    ServiceListviewSet,
    TagsListViewSet,
    VirtualMachinesListViewSet,
)

app_name = "lists"

router = DefaultRouter()
router.APIRootView = ListsRootView

router.register("prefixes", PrefixListViewSet)
router.register("ip-addresses", IPAddressListViewSet, basename="ip-addresses")
router.register("ip-ranges", IPRangeListViewSet)
router.register("aggregates", AggregateListViewSet)
router.register("services", ServiceListviewSet)
router.register("tags", TagsListViewSet)
router.register("devices", DevicesListViewSet, basename="devices")
router.register(
    "virtual-machines", VirtualMachinesListViewSet, basename="virtual-machines"
)
router.register("prometheus-devices", PrometheusDeviceSD, basename="prometheus-devices")
router.register("prometheus-vms", PrometheusVirtualMachineSD)
router.register("prometheus-ip-addresses", PrometheusIPAddressSD)

router.register("devices-vms", DevicesVMsListViewSet, basename="devices-vms")
router.register("devices-vms-attrs", DevicesVMsAttrsListViewSet)
urlpatterns = router.urls
