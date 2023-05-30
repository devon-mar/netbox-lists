PLUGINS = ["netbox_lists"]
PLUGINS_CONFIG = {
    "netbox_lists": {
        "devices_vms_attrs": [
            # This should be the same as the default but with cf.fqdn.
            ("id",),
            ("name",),
            ("role", "slug"),
            ("platform", "slug"),
            ("primary_ip", "address"),
            ("tags",),
            ("cf", "fqdn"),
        ],
        "prometheus_vm_sd_labels": {
            "__meta_netbox_id": ("id",),
            "__meta_netbox_name": ("name",),
            "__meta_netbox_status": ("status",),
            "__meta_netbox_cluster_name": ("cluster", "name"),
            "__meta_netbox_site_name": ("site", "name"),
            "__meta_netbox_role_name": ("role", "name"),
            "__meta_netbox_platform_name": ("platform", "name"),
            "__meta_netbox_primary_ip": ("primary_ip", "address", "ip"),
            "__meta_netbox_primary_ip4": ("primary_ip4", "address", "ip"),
            "__meta_netbox_primary_ip6": ("primary_ip6", "address", "ip"),
            "__meta_netbox_fqdn": ("cf", "fqdn"),
        },
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
            # A custom field. Will be an empty string if None.
            "__meta_netbox_fqdn": ("cf", "fqdn"),
        },
        "prometheus_ipaddress_sd_labels": {
            "__meta_netbox_id": ("id",),
            "__meta_netbox_role": ("role",),
            "__meta_netbox_status": ("status",),
            "__meta_netbox_dns_name": ("dns_name",),
            "__meta_netbox_assigned": ("assigned_object", "name"),
        },
    }
}
