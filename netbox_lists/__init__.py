__version__ = "2.1.1"

from typing import List

from extras.plugins import PluginConfig


class ListsPluginConfig(PluginConfig):
    name = "netbox_lists"
    verbose_name = "NetBox Lists"
    version = __version__
    author = "Devon Mar"
    base_url = "lists"
    required_settings: List[str] = []
    default_settings = {
        "as_cidr": True,
        "service_primary_ips": True,
        "summarize": True,
        "devices_vms_attrs": [
            "id",
            "name",
            "role__slug",
            "platform__slug",
            "primary_ip__address",
            "tags",
        ],
    }


config = ListsPluginConfig
