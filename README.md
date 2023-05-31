# netbox-lists

NetBox Lists generates list of IPs and prefixes from NetBox data.
While this can be accomplished using the existing NetBox API, this plugin
saves the user from having to manipulate the data to get just the IPs/prefixes. Lists endpoints (mostly) share the same filters as the builtin NetBox endpoints, making querying easy.

Lists are returned as JSON arrays or as plain text. This means that firewalls
can use NetBox as a source for dynamic address lists, such as Palo Alto's External Dynamic Lists, Fortinet's External Block List (Threat Feed) or
pfSesnse/OPNSense's firewall aliases.

This plugin also features endpoints for devices/VMs/IP addresses compatible with Prometheus' http_sd.

This plugin supports NetBox v3.0, v3.1, v3.2, v3.3, and v3.4.

## Features
* Supports NetBox's object permissions.

* [Ansible](https://galaxy.ansible.com/devon_mar/nblists) and [Terraform](https://registry.terraform.io/providers/devon-mar/nblists/latest/docs) integrations.

* Prometheus http_sd endpoint for devices/vms.

* API documented using OpenAPI.

* Supports standard NetBox object filters.

* Address family specific prefix length filters.

* JSON and plain text output formats.

## Documentation
* API documentation can be found in NetBox's builtin API docs (`/api/docs/`).

* The format of the response can be controlled by the `Accept` header (`application/json` or `text/plain`)
  or by the appending `format=(text|json)` to the URL.

* This plugin uses NetBox's object permissions. Make sure users have the appropriate permissions.

* Summarization is enabled by default.

* When summarization is enabled, all IP addresses will be returned in CIDR format regardless of the `as_cidr` setting.

## Installation
1. Add `netbox-lists` to `local_requirements.txt`.
2. Enable the plugin in `configuration.py`
    ```python
    PLUGINS = ["netbox_lists"]
    ```
3. Run `upgrade.sh`

## Plugin Config
```python
PLUGINS_CONFIG = {
    "netbox_lists": {
        # Return IPs as /32 or /128.
        # Default: True
        "as_cidr": True,
        # For services without any explicit IPs configured,
        # use the primary IPs of the associated device/vm.
        # Default: True
        "service_primary_ips": True,
        # Summarize responses
        "summarize": True,
        # A list of attributes for the devices-vms-attrs endpoint
        #
        # Attributes will be joined with "__" in the returned object.
        # eg. ("primary_ip", "address") -> primary_ip__address
        "devices_vms_attrs": [
            ("id",),
            ("name",),
            # `role` will automatically be converted to `device_role` for devices.
            # Don't use `device_role`.
            ("role", "slug"),
            ("platform", "slug"),
            ("primary_ip", "address"),
            ("tags",),
        ],
        # Tuple/list of attributes to use for Prometheus VM SD target. Defaults are shown.
        #
        # If all attributes return None, the device's name will be used.
        "prometheus_vm_sd_target": (
            # For a custom field
            # ("cf", "fqdn"),
            # If this returns none, try Name.
            ("primary_ip", "address", "ip"),
            ("name",), # not necessary
        ),
        # Dictionary of label to VM attribute for Prometheus VM SD. Defaults are shown.
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
            # A custom field. Will be an empty string if None.
            # "__meta_netbox_fqdn": ("cf", "fqdn"),
        },
        # Tuple/list of attributes to use for Prometheus device SD target. Defaults are shown.
        #
        # If all attributes return None, the device's name will be used.
        "prometheus_device_sd_target": (
            # For a custom field
            # ("cf", "fqdn"),
            ("primary_ip", "address", "ip"),
            ("name",), # not necessary
        ),
        # Dictionary of label to device attribute for Prometheus device SD. Defaults are shown.
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
            # "__meta_netbox_fqdn": ("cf", "fqdn"),
        },
        # Tuple/list of attributes to use for Prometheus IP address SD target. Defaults are shown.
        #
        # If all attributes return None, the address in CIDR format will be used.
        "prometheus_ipaddress_sd_target": (
            ("address", "ip"),
        ),
        # Dictionary of label to IP address attribute for Prometheus ip address SD. Defaults are shown.
        "prometheus_ipaddress_sd_labels": {
            "__meta_netbox_id": ("id",),
            "__meta_netbox_role": ("role",),
            "__meta_netbox_dns_name": ("dns_name",),
            "__meta_netbox_status": ("status",),
            # For addresses assigned to interfaces
            #"__meta_netbox_device": ("assigned_object", "device", "name"),
            #"__meta_netbox_interface": ("assigned_object", "name"),
        },
    }
}
```

##  Examples
1. Get all IP addresses for devices with the tag `test`.
```
https://netbox.example.com/api/plugins/lists/devices/?tag=test
```

2. Get all IP addresses for devices with the tag `test` in plain text.
```
https://netbox.example.com/api/plugins/lists/devices/?tag=test&format=text
```

3. Get all IP addresses assigned to services named `NTP`.
```
https://netbox.example.com/api/plugins/lists/services/?name=NTP
```

4. Get all IP addresses assigned to services named `NTP` and use the assigned device's primary IPs when no IPs
are explicitly configured on the service.
```
https://netbox.example.com/api/plugins/lists/services/?name=NTP&primary_ips=true
```

5. Get all IPv6 addresses for devices with the tag `test` in plain text.
```
https://netbox.example.com/api/plugins/lists/devices/?tag=test&family=6
```

6. Get all prefixes and IPs with the tag `internal`
```
https://netbox.example.com/api/plugins/lists/tags/internal/?ips&prefixes
```

7. Get all prefixes and IPs with the tag `internal` without summarization
```
https://netbox.example.com/api/plugins/lists/tags/internal/?ips&prefixes&summarize=false
```

### Ansible Usage Example

Using the [nblists collection](https://galaxy.ansible.com/devon_mar/nblists):

```yaml
# Build an ACL using all NetBox prefixes with the role 'data'
- name: Build ACL 10
  ansible.builtin.set_fact:
    acl_10_aces: "{{ acl_10_aces | default([]) + ace }}"
  vars:
    ace:
      - grant: permit
        source:
          address: "{{ item | ansible.utils.ipaddr('network') }}"
          wildcard_bits: "{{ item | ansible.utils.ipaddr('wildcard') }}"
  loop: "{{ q('devon_mar.nblists.list', 'prefixes', role='data') }}"
- name: Ensure ACLs are configured
  cisco.ios.ios_acls:
    config:
      - afi: ipv4
        acls:
          - name: 10
            aces: "{{ acl_10_aces }}"
```

### Terraform Usage Example

Using the [nblists provider](https://registry.terraform.io/providers/devon-mar/nblists/latest/docs):

```terraform
data "nblists_list" "special" {
    endpoint = "ip-addresses"
    filter = {
        tag = ["special"]
    }
}
```

### Oxidized usage

```yaml
source:
  default: http
  http:
    # Devices/VMs with the "oxidized" tag
    url: https://netbox.example.com/api/plugins/lists/devices-vms-attrs/?tag=oxidized
    scheme: https
    secure: true
    map:
      name: primary_ip__address
      model: platform__slug
    headers:
      Authorization: Token <netbox token>
```

### Prometheus usage

```yaml
http_sd_configs:
    # VMs with the role slug "linux"
  - url: https://netbox.example.com/api/plugins/lists/prometheus-vms/?role=linux
    refresh_interval: 60s
    authorization:
      type: Token
      credentials: mynetboxtoken
```
