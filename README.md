# netbox-lists

NetBox Lists generates list of IPs and prefixes from NetBox data.
While this can be accomplished using the existing NetBox API, this plugin
saves the user from having to manipulate the data to get just the IPs/prefixes. Lists endpoints (mostly) share the same filters as the builtin NetBox endpoints, making querying easy.

Lists are returned as JSON arrays or as plain text. This means that firewalls
can use NetBox as a source for dynamic address lists, such as Palo Alto's External Dynamic Lists, Fortinet's External Block List (Threat Feed) or
pfSesnse/OPNSense's firewall aliases.

This plugin also features endpoints for devices/VMs compatible with Prometheus' http_sd.

This plugin supports NetBox v3.0, v3.1, v3.2, and v3.3.

## Features
* Supports NetBox's object permissions.

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
        "service_primary_ips": True
        # Summarize responses
        "summarize": True,
        # A list of attributes for the devices-vms-attrs endpoint
        # `role` will automatically be converted to `device_role` for devices.
        "devices_vms_attrs": [
            "id",
            "name",
            "role__slug",
            "platform__slug",
            "primary_ip__address",
            "tags",
        ]
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
