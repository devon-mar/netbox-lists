# netbox-lists

NetBox Lists generates list of IPs and prefixes from NetBox data.
While this can be accomplished using the existing NetBox API, this plugin
saves the user from having to manipulate the data to get just the IPs/prefixes. Lists endpoints (mostly) share the same filters as the builtin NetBox endpoints, making querying easy.

Lists are returned as JSON arrays or as plain text. This means that firewalls
can use NetBox as a source for dynamic address lists, such as Palo Alto's External Dynamic Lists, Fortinet's External Block List (Threat Feed) or
pfSesnse/OPNSense's firewall aliases.

This plugin also features endpoints for devices/VMs compatible with Prometheus' http_sd.

## Documentation
* API documentation can be found in NetBox's builtin API docs (`/api/docs/`).

* The format of the response can be controlled by the `Accept` header (`application/json` or `text/plain`)
  or by the appending `format=(text|json)` to the URL.

* Users with only the `ipam | device` permission will be able to access VMs on the `devices-vms` endpoint.

* This plugin uses NetBox's object permissions. Make sure users have the appropriate permissions.

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

3. Get all IP addresses for devices with the tag `test` in plain text.
```
https://netbox.example.com/api/plugins/lists/devices/?tag=test&format=text
```

3. Get all IPv6 addresses for devices with the tag `test` in plain text.
```
https://netbox.example.com/api/plugins/lists/devices/?tag=test&family=6
```

4. Get all prefixes and IPs with the tag `internal`
```
https://netbox.example.com/api/plugins/lists/tags/internal/?ips&prefixes
```
