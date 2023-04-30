from itertools import chain
from typing import Dict, Generic, List, TypeVar

from dcim.models import Device
from django.conf import settings
from rest_framework import serializers
from virtualization.models import VirtualMachine

from .utils import get_attr, get_attr_str

# TODO Use in Next major version when we drop support
# for < v3.2
# from utilities.exceptions import AbortRequest


T = TypeVar("T")


class BasePrometheusSerializer(serializers.Serializer, Generic[T]):
    targets = serializers.SerializerMethodField()
    labels = serializers.SerializerMethodField()

    def get_targets(self, device: T) -> List[str]:
        # Default to Name
        for attrs in chain(
            settings.PLUGINS_CONFIG["netbox_lists"][
                f"prometheus_{self.settings_type}_sd_target"
            ],
            (("name",),),
        ):
            print(f"Attr: {repr(attrs)}")
            target = get_attr(attrs, device)
            if target is not None:
                return [str(target)]

        # This shouldn't happen since Name is a required field
        assert False, f"Name was none for {repr(device)}"
        # TODO Use in Next major version when we drop support
        # for < v3.2
        # raise AbortRequest(
        #     f"No target found for {repr(device)}. (this shouldn't happen)"
        # )

    def get_labels(self, device: T) -> Dict[str, str]:
        labels = {
            k: get_attr_str(v, device)
            for k, v in settings.PLUGINS_CONFIG["netbox_lists"][
                f"prometheus_{self.settings_type}_sd_labels"
            ].items()
        }

        # TODO: remove in next major release
        # kept for compatibility
        for k, v in device.custom_field_data.items():
            labels[f"__meta_netbox_cf_{k}"] = str(v)
        return labels


class PrometheusVMSerializer(BasePrometheusSerializer[VirtualMachine]):
    settings_type = "vm"


class PrometheusDeviceSerializer(BasePrometheusSerializer[Device]):
    settings_type = "device"
