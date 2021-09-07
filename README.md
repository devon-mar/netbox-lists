# netbox-lists

NetBox Lists generates list of IPs and prefixes from NetBox data.
While this can be accomplished using the existing NetBox API, this plugin
saves the user from having to manipulate the data to get just the IPs/prefixes.

Lists are returned as JSON arrays or as plain text. This means that firewalls
can use NetBox as a source for dynamic address lists, such as Palo Alto's External Dynamic Lists, Fortinet's External Block List (Threat Feed) or
pfSesnse/OPNSense's firewall aliases.

This plugin also features endpoints for devices/VMs compatible with Prometheus's HTTP SD.

## Documentation
* API documentation can be found in NetBox's builtin API docs (`/api/docs/`).

* The format of the response can be controlled by the `Accept` header (`application/json` or `text/plain`)
  or by the appending `format=(text|json)` to the URL.

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
        # Default: False
        "as_cidr": False
    }
}
```