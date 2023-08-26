__version__ = "3.1.1"

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
            ("id",),
            ("name",),
            ("role", "slug"),
            ("platform", "slug"),
            ("primary_ip", "address"),
            ("tags",),
        ],
        "prometheus_vm_sd_target": (
            ("primary_ip", "address", "ip"),
            ("name",),
        ),
        "prometheus_vm_sd_labels": {
            "__meta_netbox_id": ("id",),
            "__meta_netbox_name": ("name",),
            "__meta_netbox_status": ("status",),
            "__meta_netbox_cluster_name": (
                "cluster",
                "name",
            ),
            "__meta_netbox_site_name": ("site", "name"),
            "__meta_netbox_role_name": ("role", "name"),
            "__meta_netbox_platform_name": ("platform", "name"),
            "__meta_netbox_primary_ip": ("primary_ip", "address", "ip"),
            "__meta_netbox_primary_ip4": ("primary_ip4", "address", "ip"),
            "__meta_netbox_primary_ip6": ("primary_ip6", "address", "ip"),
        },
        "prometheus_device_sd_target": (
            ("primary_ip", "address", "ip"),
            ("name",),
        ),
        "prometheus_device_sd_labels": {
            "__meta_netbox_id": ("id",),
            "__meta_netbox_name": ("name",),
            "__meta_netbox_status": ("status",),
            "__meta_netbox_site_name": ("site", "name"),
            "__meta_netbox_platform_name": ("platform", "name"),
            "__meta_netbox_primary_ip": ("primary_ip", "address", "ip"),
            "__meta_netbox_primary_ip4": ("primary_ip4", "address", "ip"),
            "__meta_netbox_primary_ip6": ("primary_ip6", "address", "ip"),
            "__meta_netbox_serial": ("serial",),
        },
        "prometheus_ipaddress_sd_target": (("address", "ip"),),
        "prometheus_ipaddress_sd_labels": {
            "__meta_netbox_id": ("id",),
            "__meta_netbox_role": ("role",),
            "__meta_netbox_dns_name": ("dns_name",),
            "__meta_netbox_status": ("status",),
        },
    }


config = ListsPluginConfig
