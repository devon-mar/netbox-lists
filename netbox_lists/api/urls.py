from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (
    AggregateListViewSet,
    DevicesListViewSet,
    DevicesVMsAttrsListView,
    DevicesVMsListView,
    IPAddressListViewSet,
    IPRangeListViewSet,
    ListsRootView,
    PrefixListViewSet,
    PrometheusDeviceSD,
    PrometheusVirtualMachineSD,
    ServiceListviewSet,
    TagsListViewSet,
    VirtualMachinesListViewSet,
)

app_name = "lists"

router = DefaultRouter()
router.APIRootView = ListsRootView

router.register("prefixes", PrefixListViewSet)
router.register("ip-addresses", IPAddressListViewSet)
router.register("ip-ranges", IPRangeListViewSet)
router.register("aggregates", AggregateListViewSet)
router.register("services", ServiceListviewSet)
router.register("tags", TagsListViewSet)
router.register("devices", DevicesListViewSet, basename="devices")
router.register(
    "virtual-machines", VirtualMachinesListViewSet, basename="virtual-machines"
)
router.register("prometheus-devices", PrometheusDeviceSD)
router.register("prometheus-vms", PrometheusVirtualMachineSD)

urlpatterns = [
    path("devices-vms/", DevicesVMsListView.as_view()),
    path("devices-vms-attrs/", DevicesVMsAttrsListView.as_view()),
]
urlpatterns += router.urls
