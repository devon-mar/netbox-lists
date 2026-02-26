from collections.abc import Iterator
from typing import Any, Literal

import pynetbox
import pytest
import requests
from pynetbox.core import endpoint, response

nb_objects: list[response.Record] = []

TestUser = Literal["no_permissions", "constraint"]
API_TOKENS: dict[TestUser, str] = {}


def nb_cleanup():
    nb_objects.reverse()
    for obj in nb_objects:
        try:
            obj.delete()
        except Exception as e:  # noqa: PERF203
            print(f"Error deleting {repr(obj)}: {repr(e)}")


def nb_create(ep: endpoint.Endpoint, **kwargs):
    try:
        obj = ep.create(**kwargs)
        nb_objects.append(obj)
        return obj
    except Exception as e:
        print(f"Error creating on endpoint {repr(ep)} with args {kwargs}: {repr(e)}")
        nb_cleanup()
        raise e


def nb_update(r: response.Record, update_dict: dict):
    try:
        r.update(update_dict)
    except Exception as e:
        print(f"Error updating {repr(r)} with {update_dict}: {repr(e)}")
        nb_cleanup()
        raise e


def provision_token(username: str, password: str) -> str:
    resp = requests.post(
        "http://localhost:8000/api/users/tokens/provision/",
        json={"username": username, "password": password},
    )

    resp.raise_for_status()

    data = resp.json()

    if data.get("version") == 2:
        return f"nbt_{data['key']}.{data['token']}"
    else:
        return data["key"]


@pytest.fixture(scope="session")
def netbox_token() -> str:
    return provision_token("admin", "admin")


@pytest.fixture(scope="session")
def nb_requests(netbox_token: str) -> requests.Session:
    s = requests.session()
    s.headers["Authorization"] = f"Token {netbox_token}"
    s.headers["Accept"] = "application/json"
    return s


@pytest.fixture(scope="session")
def nb_api(netbox_token: str) -> Iterator[pynetbox.api]:
    api = pynetbox.api("http://localhost:8000", token=netbox_token)

    nb_create(
        api.extras.custom_fields,
        name="fqdn",
        type="text",
        object_types=["dcim.device", "virtualization.virtualmachine"],
    )
    test_tag = nb_create(api.extras.tags, name="Test Tag", slug="test-tag")
    test_device_tag = nb_create(
        api.extras.tags, name="Test Device Tag", slug="test-device-tag"
    )
    _test_range_tag = nb_create(
        api.extras.tags, name="Test range tag", slug="test-range-tag"
    )
    test_site = nb_create(api.dcim.sites, name="Test Site", slug="test-site")
    test_device_role = nb_create(
        api.dcim.device_roles, name="Test Role", slug="test-role"
    )
    test_device_role_2 = nb_create(
        api.dcim.device_roles, name="Test Role2", slug="test-role2"
    )
    test_manufacturer = nb_create(
        api.dcim.manufacturers, name="Test Manufacturer", slug="test-manufacturer"
    )
    test_device_type = nb_create(
        api.dcim.device_types,
        manufacturer=test_manufacturer.id,
        model="test model",
        slug="test-model",
    )
    test_device_1 = nb_create(
        api.dcim.devices,
        name="Test Device 1",
        device_type=test_device_type.id,
        site=test_site.id,
        tags=[test_device_tag.id],
        custom_fields={"fqdn": "device-1.example.com"},
        role=test_device_role.id,
    )
    test_device_1_intf_1 = nb_create(
        api.dcim.interfaces,
        name="GigabitEthernet1/1",
        type="1000base-t",
        device=test_device_1.id,
    )
    test_device_1_intf_1_ip_1 = nb_create(
        api.ipam.ip_addresses,
        address="192.0.2.1/24",
        role="secondary",
        dns_name="device-1.example.com",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_1_intf_1.id,
    )
    test_device_1_intf_1_ip_2 = nb_create(
        api.ipam.ip_addresses,
        address="2001:db8::1/128",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_1_intf_1.id,
    )
    # Set the primary IP
    nb_update(
        test_device_1,
        {
            "primary_ip4": test_device_1_intf_1_ip_1.id,
            "primary_ip6": test_device_1_intf_1_ip_2.id,
        },
    )

    test_device_2 = nb_create(
        api.dcim.devices,
        name="Test-Device-2",
        device_type=test_device_type.id,
        site=test_site.id,
        tags=[test_tag.id],
        role=test_device_role_2.id,
    )
    test_device_2_intf_1 = nb_create(
        api.dcim.interfaces,
        name="GigabitEthernet1/1",
        type="1000base-t",
        device=test_device_2.id,
    )
    test_device_2_intf_1_ip_1 = nb_create(
        api.ipam.ip_addresses,
        address="192.0.2.2/24",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_2_intf_1.id,
        tags=[test_tag.id],
    )
    # A duplicate IP of test_device_1 but with a different prefix length.
    # Used to test that duplicate IPs don't appear.
    test_device_2_intf_1_ip_2 = nb_create(
        api.ipam.ip_addresses,
        address="2001:db8::1/127",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_2_intf_1.id,
        tags=[test_tag.id],
    )
    _test_device_2_svc_1 = nb_create(
        api.ipam.services,
        name="DNS",
        ports=[53],
        protocol="udp",
        parent_object_type="dcim.device",
        parent_object_id=test_device_2.id,
        device=test_device_2.id,
        ipaddresses=[test_device_2_intf_1_ip_1.id],
    )
    _test_device_2_svc_2 = nb_create(
        api.ipam.services,
        name="HTTP",
        ports=[80],
        protocol="tcp",
        parent_object_type="dcim.device",
        parent_object_id=test_device_2.id,
        device=test_device_2.id,
        ipaddresses=[test_device_2_intf_1_ip_1.id, test_device_2_intf_1_ip_2.id],
        tags=[test_tag.id],
    )
    test_device_3 = nb_create(
        api.dcim.devices,
        name="Test-Device-3",
        device_type=test_device_type.id,
        site=test_site.id,
        tags=[],
        role=test_device_role_2.id,
    )
    test_device_3_intf_1 = nb_create(
        api.dcim.interfaces,
        name="GigabitEthernet1/1",
        type="1000base-t",
        device=test_device_3.id,
    )
    test_device_3_intf_1_ip_1 = nb_create(
        api.ipam.ip_addresses,
        address="192.0.2.5/24",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_3_intf_1.id,
    )
    test_device_3_intf_1_ip_2 = nb_create(
        api.ipam.ip_addresses,
        address="2001:db8::dead:beef:1/64",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_3_intf_1.id,
    )
    # Set the primary IP
    nb_update(
        test_device_3,
        {
            "primary_ip4": test_device_3_intf_1_ip_1.id,
            "primary_ip6": test_device_3_intf_1_ip_2.id,
        },
    )
    _test_device_4_no_name = nb_create(
        api.dcim.devices,
        # no Name
        device_type=test_device_type.id,
        site=test_site.id,
        role=test_device_role_2.id,
    )
    test_cluster_type = nb_create(
        api.virtualization.cluster_types,
        name="test cluster type",
        slug="test-cluster-type",
    )
    test_cluster = nb_create(
        api.virtualization.clusters, name="Test Cluster", type=test_cluster_type.id
    )
    test_vm_1 = nb_create(
        api.virtualization.virtual_machines,
        name="VM1",
        cluster=test_cluster.id,
        role=test_device_role.id,
        tags=[test_tag.id],
        custom_fields={"fqdn": "vm-1.example.com"},
    )
    test_vm_1_intf_1 = nb_create(
        api.virtualization.interfaces, name="eth0", virtual_machine=test_vm_1.id
    )
    test_vm_1_intf_2 = nb_create(
        api.virtualization.interfaces, name="eth1", virtual_machine=test_vm_1.id
    )
    test_vm_1_intf_1_ip_1 = nb_create(
        api.ipam.ip_addresses,
        address="192.0.2.3/24",
        assigned_object_type="virtualization.vminterface",
        assigned_object_id=test_vm_1_intf_1.id,
    )
    test_vm_1_intf_1_ip_2 = nb_create(
        api.ipam.ip_addresses,
        address="2001:db8::3/128",
        assigned_object_type="virtualization.vminterface",
        assigned_object_id=test_vm_1_intf_1.id,
    )
    _test_vm_1_intf_2_ip_1 = nb_create(
        api.ipam.ip_addresses,
        address="192.0.2.4/24",
        assigned_object_type="virtualization.vminterface",
        assigned_object_id=test_vm_1_intf_2.id,
    )
    # This service has no assigned IPs.
    _test_device_2_svc_1 = nb_create(
        api.ipam.services,
        name="HTTP",
        ports=[80],
        protocol="tcp",
        parent_object_type="virtualization.virtualmachine",
        parent_object_id=test_vm_1.id,
        virtual_machine=test_vm_1.id,
        tags=[test_tag.id],
    )
    # Set primary IP for VM1
    nb_update(
        test_vm_1,
        {
            "primary_ip4": test_vm_1_intf_1_ip_1.id,
            "primary_ip6": test_vm_1_intf_1_ip_2.id,
        },
    )

    _test_vm_2 = nb_create(
        api.virtualization.virtual_machines,
        name="VM2",
        cluster=test_cluster.id,
        role=test_device_role_2.id,
    )

    _test_prefix_1 = nb_create(api.ipam.prefixes, prefix="192.0.2.0/24")
    _test_prefix_2 = nb_create(
        api.ipam.prefixes, prefix="192.0.2.32/27", tags=[test_tag.id]
    )
    _test_prefix_3 = nb_create(
        api.ipam.prefixes, prefix="2001:db8:2::/64", tags=[test_tag.id]
    )
    _test_prefix_4 = nb_create(api.ipam.prefixes, prefix="2001:db8:3::/127")
    test_rir = nb_create(api.ipam.rirs, name="test rir", slug="test-rir")
    _test_aggregate_1 = nb_create(
        api.ipam.aggregates, prefix="10.0.0.0/8", rir=test_rir.id
    )
    _test_aggregate_2 = nb_create(
        api.ipam.aggregates, prefix="172.16.0.0/12", rir=test_rir.id, tags=[test_tag.id]
    )
    _test_aggregate_3 = nb_create(
        api.ipam.aggregates, prefix="2001:db8::/32", rir=test_rir.id, tags=[test_tag.id]
    )
    _test_range_1 = nb_create(
        api.ipam.ip_ranges,
        start_address="198.51.100.10/24",
        end_address="198.51.100.99/24",
    )
    _test_range_2 = nb_create(
        api.ipam.ip_ranges,
        start_address="198.51.100.100/24",
        end_address="198.51.100.127/24",
    )
    _test_range_3 = nb_create(
        api.ipam.ip_ranges,
        start_address="2001:db8:f00d::100/64",
        end_address="2001:db8:f00d::203/64",
    )
    _test_range_4 = nb_create(
        api.ipam.ip_ranges,
        start_address="2001:db8:f00d::204/64",
        end_address="2001:db8:f00d::23f/64",
    )
    password = "Passw0rd12Characters"
    no_perm_user = nb_create(
        api.users.users, username="no_permissions", password=password
    )
    _no_perm = nb_create(
        api.users.permissions,
        name="no_permissions",
        object_types=[],
        actions=["view"],
        users=[no_perm_user.id],
    )
    token = provision_token(no_perm_user.username, password=password)
    API_TOKENS["no_permissions"] = (
        f"Bearer {token}" if token.startswith("nbt_") else f"Token {token}"
    )

    constraint_user = nb_create(
        api.users.users, username="constraint_user", password="Passw0rd12Characters"
    )
    _constraint_permissions = nb_create(
        api.users.permissions,
        name="constraint_permissions",
        object_types=[
            "dcim.device",
            "ipam.aggregate",
            "ipam.ipaddress",
            "ipam.prefix",
            "ipam.service",
            "ipam.iprange",
            "extras.tag",
            "virtualization.virtualmachine",
            "virtualization.vminterface",
        ],
        actions=["view"],
        users=[constraint_user.id],
        constraints={"id__lt": 0},
    )
    token = provision_token(constraint_user.username, password=password)
    API_TOKENS["constraint"] = (
        f"Bearer {token}" if token.startswith("nbt_") else f"Token {token}"
    )

    yield api
    nb_cleanup()


@pytest.mark.parametrize(
    "url,expected",
    [
        #
        # IP Address Test Cases
        #
        (
            "http://localhost:8000/api/plugins/lists/ip-addresses?as_cidr=false&summarize=false",
            [
                "192.0.2.1",
                "192.0.2.2",
                "192.0.2.3",
                "192.0.2.4",
                "192.0.2.5",
                "2001:db8::1",
                "2001:db8::3",
                "2001:db8::dead:beef:1",
            ],
        ),
        (
            # Summarize overrides as_cidr
            "http://localhost:8000/api/plugins/lists/ip-addresses?as_cidr=false",
            [
                "192.0.2.1/32",
                "192.0.2.2/31",
                "192.0.2.4/31",
                "2001:db8::1/128",
                "2001:db8::3/128",
                "2001:db8::dead:beef:1/128",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-addresses?as_cidr=true",
            [
                "192.0.2.1/32",
                "192.0.2.2/31",
                "192.0.2.4/31",
                "2001:db8::1/128",
                "2001:db8::3/128",
                "2001:db8::dead:beef:1/128",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-addresses?family=4",
            ["192.0.2.1/32", "192.0.2.2/31", "192.0.2.4/31"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-addresses?family=4&summarize=false",
            [
                "192.0.2.1/32",
                "192.0.2.2/32",
                "192.0.2.3/32",
                "192.0.2.4/32",
                "192.0.2.5/32",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-addresses?family=4&as_cidr=false&summarize=false",
            ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"],
        ),
        #
        # IP Ranges
        #
        (
            "http://localhost:8000/api/plugins/lists/ip-ranges",
            [
                "198.51.100.10/31",
                "198.51.100.12/30",
                "198.51.100.16/28",
                "198.51.100.32/27",
                "198.51.100.64/26",
                "2001:db8:f00d::100/120",
                "2001:db8:f00d::200/122",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-ranges?summarize=false",
            [
                # First Range
                "198.51.100.10/31",
                "198.51.100.12/30",
                "198.51.100.16/28",
                "198.51.100.32/27",
                "198.51.100.64/27",
                "198.51.100.96/30",
                # Second range
                "198.51.100.100/30",
                "198.51.100.104/29",
                "198.51.100.112/28",
                # IP Range 3
                "2001:db8:f00d::100/120",
                "2001:db8:f00d::200/126",
                # IP Range 4
                "2001:db8:f00d::204/126",
                "2001:db8:f00d::208/125",
                "2001:db8:f00d::210/124",
                "2001:db8:f00d::220/123",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-ranges?family=6",
            ["2001:db8:f00d::100/120", "2001:db8:f00d::200/122"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-ranges?family=6&summarize=false",
            [
                # IP Range 3
                "2001:db8:f00d::100/120",
                "2001:db8:f00d::200/126",
                # IP Range 4
                "2001:db8:f00d::204/126",
                "2001:db8:f00d::208/125",
                "2001:db8:f00d::210/124",
                "2001:db8:f00d::220/123",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-ranges?family=4&summarize=false",
            [
                # First Range
                "198.51.100.10/31",
                "198.51.100.12/30",
                "198.51.100.16/28",
                "198.51.100.32/27",
                "198.51.100.64/27",
                "198.51.100.96/30",
                # Second range
                "198.51.100.100/30",
                "198.51.100.104/29",
                "198.51.100.112/28",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-ranges?family=4",
            [
                "198.51.100.10/31",
                "198.51.100.12/30",
                "198.51.100.16/28",
                "198.51.100.32/27",
                "198.51.100.64/26",
            ],
        ),
        #
        # Prefixes
        #
        (
            "http://localhost:8000/api/plugins/lists/prefixes",
            ["192.0.2.0/24", "2001:db8:2::/64", "2001:db8:3::/127"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/prefixes?summarize=false",
            ["192.0.2.0/24", "192.0.2.32/27", "2001:db8:2::/64", "2001:db8:3::/127"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/prefixes?mask_length4=24",
            ["192.0.2.0/24", "2001:db8:2::/64", "2001:db8:3::/127"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/prefixes?mask_length6=64",
            ["192.0.2.0/24", "2001:db8:2::/64"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/prefixes?mask_length6__gte=70",
            ["192.0.2.0/24", "2001:db8:3::/127"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/prefixes?mask_length6__lte=126",
            ["192.0.2.0/24", "2001:db8:2::/64"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/prefixes?mask_length4__lte=26",
            ["192.0.2.0/24", "2001:db8:2::/64", "2001:db8:3::/127"],
        ),
        # Summarization shoiuld happen after filtering
        (
            "http://localhost:8000/api/plugins/lists/prefixes?mask_length4__gte=26",
            ["192.0.2.32/27", "2001:db8:2::/64", "2001:db8:3::/127"],
        ),
        #
        # Aggregates
        #
        (
            "http://localhost:8000/api/plugins/lists/aggregates",
            ["10.0.0.0/8", "172.16.0.0/12", "2001:db8::/32"],
        ),
        #
        # Services
        #
        (
            "http://localhost:8000/api/plugins/lists/services?as_cidr=false&summarize=false",
            ["192.0.2.2", "2001:db8::1", "192.0.2.3", "2001:db8::3"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/services?as_cidr=false&summarize=false&primary_ips=false",
            ["192.0.2.2", "2001:db8::1"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/services?as_cidr=false&summarize=false&primary_ips=false&family=4",
            ["192.0.2.2"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/services?family=6",
            ["2001:db8::1/128", "2001:db8::3/128"],
        ),
        ("http://localhost:8000/api/plugins/lists/services?name=DNS", ["192.0.2.2/32"]),
        #
        # Devices
        #
        (
            "http://localhost:8000/api/plugins/lists/devices?as_cidr=false&summarize=false",
            ["192.0.2.1", "2001:db8::1", "192.0.2.5", "2001:db8::dead:beef:1"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices?family=4",
            ["192.0.2.1/32", "192.0.2.5/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices?family=6&as_cidr=false&summarize=false",
            ["2001:db8::1", "2001:db8::dead:beef:1"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices?cf_fqdn=example.com",
            ["192.0.2.1/32", "2001:db8::1/128"],
        ),
        #
        # Virtual Machines
        #
        (
            "http://localhost:8000/api/plugins/lists/virtual-machines?as_cidr=false&summarize=false",
            ["192.0.2.3", "2001:db8::3"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/virtual-machines?family=4&as_cidr=false&summarize=false",
            ["192.0.2.3"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/virtual-machines?family=6",
            ["2001:db8::3/128"],
        ),
        #
        # Devices-VMs
        #
        (
            "http://localhost:8000/api/plugins/lists/devices-vms",
            [
                "192.0.2.1/32",
                "2001:db8::1/128",
                "192.0.2.3/32",
                "2001:db8::3/128",
                "192.0.2.5/32",
                "2001:db8::dead:beef:1/128",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms?as_cidr=false&summarize=false",
            [
                "192.0.2.1",
                "2001:db8::1",
                "192.0.2.3",
                "2001:db8::3",
                "192.0.2.5",
                "2001:db8::dead:beef:1",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms?as_cidr=true&name=VM1",
            ["192.0.2.3/32", "2001:db8::3/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms?as_cidr=true&name=VM1&family=6",
            ["2001:db8::3/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms?as_cidr=true&name=Test Device 1",
            ["192.0.2.1/32", "2001:db8::1/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms?as_cidr=true&name=Test Device 1&family=4",
            ["192.0.2.1/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms?role=test-role",
            [
                # Test Device 1
                "2001:db8::1/128",
                "192.0.2.1/32",
                # VM1
                "2001:db8::3/128",
                "192.0.2.3/32",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms?role=test-role2",
            [
                # Test Device 3
                "2001:db8::dead:beef:1/128",
                "192.0.2.5/32",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms?cf_fqdn=example.com",
            [
                # Test Device 1
                "192.0.2.1/32",
                "2001:db8::1/128",
                # VM1
                "2001:db8::3/128",
                "192.0.2.3/32",
            ],
        ),
        #
        # Tags
        #
        # NOTE: IPs should always be returned as /32s or /128s
        # Test a tag containing only device 1
        (
            "http://localhost:8000/api/plugins/lists/tags/test-device-tag?devices",
            ["192.0.2.1/32", "2001:db8::1/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-device-tag?devices&family=4",
            ["192.0.2.1/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-device-tag?devices&family=6",
            ["2001:db8::1/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-device-tag?ips&aggregates&vms",
            [],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-device-tag?devices_primary",
            ["192.0.2.1/32", "2001:db8::1/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-device-tag?devices_primary&family=4",
            ["192.0.2.1/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-device-tag?devices_primary&family=6",
            ["2001:db8::1/128"],
        ),
        # Should return only device 2 IPs
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?devices",
            ["192.0.2.2/32", "2001:db8::1/128"],
        ),
        ("http://localhost:8000/api/plugins/lists/tags/test-tag?devices_primary", []),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?ips",
            ["192.0.2.2/32", "2001:db8::1/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?ips&family=4",
            ["192.0.2.2/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?ips&family=6",
            ["2001:db8::1/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?aggregates",
            ["172.16.0.0/12", "2001:db8::/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?aggregates&family=4",
            ["172.16.0.0/12"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?aggregates&family=6",
            ["2001:db8::/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?prefixes",
            ["192.0.2.32/27", "2001:db8:2::/64"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?prefixes&family=4",
            ["192.0.2.32/27"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?prefixes&family=6",
            ["2001:db8:2::/64"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?vms",
            ["192.0.2.3/32", "192.0.2.4/32", "2001:db8::3/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?vms&family=4",
            ["192.0.2.3/32", "192.0.2.4/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?vms&family=6",
            ["2001:db8::3/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?vms_primary",
            ["192.0.2.3/32", "2001:db8::3/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?vms_primary&family=4",
            ["192.0.2.3/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?vms_primary&family=6",
            ["2001:db8::3/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?services",
            ["192.0.2.2/31", "2001:db8::1/128", "2001:db8::3/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?services&summarize=false",
            ["192.0.2.2/32", "2001:db8::1/128", "192.0.2.3/32", "2001:db8::3/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?services&service_primary_ips=false",
            ["192.0.2.2/32", "2001:db8::1/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?services&family=4&service_primary_ips=false",
            ["192.0.2.2/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?services&family=4",
            ["192.0.2.2/31"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?services&family=4&summarize=false",
            ["192.0.2.2/32", "192.0.2.3/32"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?services&family=6",
            ["2001:db8::1/128", "2001:db8::3/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?ips&aggregates&prefixes",
            [
                "192.0.2.2/32",
                "172.16.0.0/12",
                "192.0.2.32/27",
                "2001:db8::/32",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?ips&aggregates&prefixes&summarize=false",
            [
                "192.0.2.2/32",
                "2001:db8::1/128",
                "172.16.0.0/12",
                "192.0.2.32/27",
                "2001:db8:2::/64",
                "2001:db8::/32",
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-device-tag?all",
            # Should be the same as /tags/test-device-tag/?devices
            ["192.0.2.1/32", "2001:db8::1/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-device-tag?all_primary",
            # Should be the same as /tags/test-device-tag/?devices_primary
            ["192.0.2.1/32", "2001:db8::1/128"],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?all",
            [
                # devices
                "192.0.2.2/31",
                # ips - all device 2 IPs
                # aggregates
                "172.16.0.0/12",
                "2001:db8::/32",
                # ?prefixes
                "192.0.2.32/27",
                # ?vms
                "192.0.2.4/32",
                # ?services - duplicate IPs so it shouldn't be included.
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?all&summarize=false",
            [
                # devices
                "192.0.2.2/32",
                "2001:db8::1/128",  # Test Device 2 IPs
                # ips - all device 2 IPs
                # aggregates
                "172.16.0.0/12",
                "2001:db8::/32",
                # ?prefixes
                "192.0.2.32/27",
                "2001:db8:2::/64",
                # ?vms
                "192.0.2.3/32",
                "192.0.2.4/32",
                "2001:db8::3/128",
                # ?services - duplicate IPs so it shouldn't be included.
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?all_primary",
            [
                # ?devices - None. Device 2 doesn't have any primary IPs set and device 1 has a different tag.
                # ?ips
                "192.0.2.2/31",
                # ?aggregates
                "172.16.0.0/12",
                "2001:db8::/32",
                # ?prefixes
                "192.0.2.32/27",
                # ?vms
                # ?services - duplicate so it shouldn't be included.
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?all_primary&summarize=false",
            [
                # ?devices - None. Device 2 doesn't have any primary IPs set and device 1 has a different tag.
                # ?ips
                "192.0.2.2/32",
                "2001:db8::1/128",
                # ?aggregates
                "172.16.0.0/12",
                "2001:db8::/32",
                # ?prefixes
                "192.0.2.32/27",
                "2001:db8:2::/64",
                # ?vms
                "192.0.2.3/32",
                "2001:db8::3/128",
                # ?services - duplicate so it shouldn't be included.
            ],
        ),
    ],
)
def test_lists(
    nb_api: pynetbox.api, nb_requests: requests.Session, url: str, expected: list[str]
):
    req = nb_requests.get(url)
    assert req.status_code == 200
    resp = req.json()

    assert isinstance(resp, list)
    assert sorted(resp) == sorted(expected)

    # User with no permissions test
    req = requests.get(
        url,
        headers={
            "Authorization": API_TOKENS["no_permissions"],
            "Accept": "application/json",
        },
    )
    assert req.status_code == 403

    req = requests.get(
        url,
        headers={
            "Authorization": API_TOKENS["constraint"],
            "Accept": "application/json",
        },
    )
    assert req.status_code == 200
    assert req.json() == []


def test_lists_txt(nb_api: pynetbox.api, nb_requests: requests.Session):
    with_header = nb_requests.get(
        "http://localhost:8000/api/plugins/lists/ip-addresses?summarize=false",
        headers={"Accept": "text/plain"},
    )
    with_format = nb_requests.get(
        "http://localhost:8000/api/plugins/lists/ip-addresses?format=text&summarize=false",
        headers={"Accept": "*/*"},
    )
    ip_only = nb_requests.get(
        "http://localhost:8000/api/plugins/lists/ip-addresses?format=text&as_cidr=false&summarize=false",
        headers={"Accept": "*/*"},
    )
    for txt_req in (with_header, with_format, ip_only):
        assert txt_req.headers["Content-Type"].startswith("text/plain")

    assert sorted(with_header.text.splitlines()) == sorted(
        with_format.text.splitlines()
    )

    assert sorted(with_header.text.splitlines()) == [
        "192.0.2.1/32",
        "192.0.2.2/32",
        "192.0.2.3/32",
        "192.0.2.4/32",
        "192.0.2.5/32",
        "2001:db8::1/128",
        "2001:db8::3/128",
        "2001:db8::dead:beef:1/128",
    ]
    assert sorted(ip_only.text.splitlines()) == [
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
        "192.0.2.4",
        "192.0.2.5",
        "2001:db8::1",
        "2001:db8::3",
        "2001:db8::dead:beef:1",
    ]


@pytest.mark.parametrize(
    "url,expected",
    [
        #
        # Device SD
        #
        (
            "http://localhost:8000/api/plugins/lists/prometheus-devices/",
            [
                {
                    "targets": ["2001:db8::1"],
                    "labels": {
                        "__meta_netbox_name": "Test Device 1",
                        "__meta_netbox_platform_name": "",
                        "__meta_netbox_primary_ip": "2001:db8::1",
                        "__meta_netbox_primary_ip4": "192.0.2.1",
                        "__meta_netbox_primary_ip6": "2001:db8::1",
                        "__meta_netbox_serial": "",
                        "__meta_netbox_site_name": "Test Site",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_fqdn": "device-1.example.com",
                    },
                },
                {
                    # Fallback to the device name if a primary ip isn't set.
                    "targets": ["Test-Device-2"],
                    "labels": {
                        "__meta_netbox_name": "Test-Device-2",
                        "__meta_netbox_platform_name": "",
                        "__meta_netbox_primary_ip": "",
                        "__meta_netbox_primary_ip4": "",
                        "__meta_netbox_primary_ip6": "",
                        "__meta_netbox_serial": "",
                        "__meta_netbox_site_name": "Test Site",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_fqdn": "",
                    },
                },
                {
                    # Fallback to the device name if a primary ip isn't set.
                    "targets": ["2001:db8::dead:beef:1"],
                    "labels": {
                        "__meta_netbox_name": "Test-Device-3",
                        "__meta_netbox_platform_name": "",
                        "__meta_netbox_primary_ip": "2001:db8::dead:beef:1",
                        "__meta_netbox_primary_ip4": "192.0.2.5",
                        "__meta_netbox_primary_ip6": "2001:db8::dead:beef:1",
                        "__meta_netbox_serial": "",
                        "__meta_netbox_site_name": "Test Site",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_fqdn": "",
                    },
                },
            ],
        ),
        # Test filters
        (
            "http://localhost:8000/api/plugins/lists/prometheus-devices/?name=Test Device 1",
            [
                {
                    "targets": ["2001:db8::1"],
                    "labels": {
                        "__meta_netbox_name": "Test Device 1",
                        "__meta_netbox_platform_name": "",
                        "__meta_netbox_primary_ip": "2001:db8::1",
                        "__meta_netbox_primary_ip4": "192.0.2.1",
                        "__meta_netbox_primary_ip6": "2001:db8::1",
                        "__meta_netbox_serial": "",
                        "__meta_netbox_site_name": "Test Site",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_fqdn": "device-1.example.com",
                    },
                }
            ],
        ),
        #
        # VM SD
        #
        (
            "http://localhost:8000/api/plugins/lists/prometheus-vms/",
            [
                {
                    "targets": ["2001:db8::3"],
                    "labels": {
                        "__meta_netbox_name": "VM1",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_cluster_name": "Test Cluster",
                        "__meta_netbox_site_name": "",
                        "__meta_netbox_platform_name": "",
                        "__meta_netbox_primary_ip": "2001:db8::3",
                        "__meta_netbox_primary_ip4": "192.0.2.3",
                        "__meta_netbox_primary_ip6": "2001:db8::3",
                        "__meta_netbox_fqdn": "vm-1.example.com",
                    },
                },
                {
                    # Fallback to the VM name if a primary ip isn't set.
                    "targets": ["VM2"],
                    "labels": {
                        "__meta_netbox_name": "VM2",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_cluster_name": "Test Cluster",
                        "__meta_netbox_site_name": "",
                        "__meta_netbox_platform_name": "",
                        "__meta_netbox_primary_ip": "",
                        "__meta_netbox_primary_ip4": "",
                        "__meta_netbox_primary_ip6": "",
                        "__meta_netbox_fqdn": "",
                    },
                },
            ],
        ),
        # Test a filter
        (
            "http://localhost:8000/api/plugins/lists/prometheus-vms/?name=VM2",
            [
                {
                    # Fallback to the VM name if a primary ip isn't set.
                    "targets": ["VM2"],
                    "labels": {
                        "__meta_netbox_name": "VM2",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_cluster_name": "Test Cluster",
                        "__meta_netbox_site_name": "",
                        "__meta_netbox_platform_name": "",
                        "__meta_netbox_primary_ip": "",
                        "__meta_netbox_primary_ip4": "",
                        "__meta_netbox_primary_ip6": "",
                        "__meta_netbox_fqdn": "",
                    },
                }
            ],
        ),
        #
        # IP Addresses SD
        #
        (
            "http://localhost:8000/api/plugins/lists/prometheus-ip-addresses/",
            [
                {
                    "targets": ["192.0.2.1"],
                    "labels": {
                        "__meta_netbox_role": "secondary",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "device-1.example.com",
                        "__meta_netbox_assigned": "GigabitEthernet1/1",
                    },
                },
                {
                    "targets": ["2001:db8::1"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "GigabitEthernet1/1",
                    },
                },
                {
                    "targets": ["192.0.2.2"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "GigabitEthernet1/1",
                    },
                },
                {
                    "targets": ["2001:db8::1"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "GigabitEthernet1/1",
                    },
                },
                {
                    "targets": ["192.0.2.5"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "GigabitEthernet1/1",
                    },
                },
                {
                    "targets": ["2001:db8::dead:beef:1"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "GigabitEthernet1/1",
                    },
                },
                {
                    "targets": ["192.0.2.3"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "eth0",
                    },
                },
                {
                    "targets": ["2001:db8::3"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "eth0",
                    },
                },
                {
                    "targets": ["192.0.2.4"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "eth1",
                    },
                },
            ],
        ),
        # Test a filter
        (
            "http://localhost:8000/api/plugins/lists/prometheus-ip-addresses/?device=Test-Device-2",
            [
                {
                    "targets": ["192.0.2.2"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "GigabitEthernet1/1",
                    },
                },
                {
                    "targets": ["2001:db8::1"],
                    "labels": {
                        "__meta_netbox_role": "",
                        "__meta_netbox_status": "active",
                        "__meta_netbox_dns_name": "",
                        "__meta_netbox_assigned": "GigabitEthernet1/1",
                    },
                },
            ],
        ),
        # Device with no name.
        (
            "http://localhost:8000/api/plugins/lists/prometheus-devices/?name__empty=True",
            [],
        ),
    ],
)
def test_prom_sd(
    nb_api: pynetbox.api,
    nb_requests: requests.Session,
    url: str,
    expected: list[dict[str, Any]],
):
    resp = nb_requests.get(url).json()

    assert isinstance(resp, list)
    assert len(resp) == len(expected)

    resp_sorted = sorted(resp, key=lambda x: x["targets"][0])
    expected_sorted = sorted(expected, key=lambda x: x["targets"][0])
    for i in range(len(expected)):
        have = resp_sorted[i]
        want = expected_sorted[i]
        assert have["targets"] == want["targets"]

        for k, v in want["labels"].items():
            if k not in have["labels"]:
                pytest.fail(f"Label {k} is missing for {want['targets']}")
            assert have["labels"][k] == v, f"Target {want['targets']}"
            assert isinstance(have["labels"][k], str)

        for k, v in have["labels"].items():
            assert isinstance(v, str), f"{k}: value was not a str, was {type(v)}"


@pytest.mark.parametrize(
    "url,expected",
    [
        (
            "http://localhost:8000/api/plugins/lists/devices-vms-attrs/?tag=test-device-tag",
            [
                {
                    "name": "Test Device 1",
                    "role__slug": "test-role",
                    "platform__slug": None,
                    "primary_ip__address": "2001:db8::1/128",
                    "tags": ["test-device-tag"],
                    "cf__fqdn": "device-1.example.com",
                },
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms-attrs/?role=test-role",
            [
                {
                    "name": "VM1",
                    "role__slug": "test-role",
                    "platform__slug": None,
                    "primary_ip__address": "2001:db8::3/128",
                    "tags": ["test-tag"],
                    "cf__fqdn": "vm-1.example.com",
                },
                {
                    "name": "Test Device 1",
                    "role__slug": "test-role",
                    "platform__slug": None,
                    "primary_ip__address": "2001:db8::1/128",
                    "tags": ["test-device-tag"],
                    "cf__fqdn": "device-1.example.com",
                },
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms-attrs/?role=test-role2",
            [
                {
                    "name": "VM2",
                    "role__slug": "test-role2",
                    "platform__slug": None,
                    "primary_ip__address": None,
                    "tags": [],
                    "cf__fqdn": None,
                },
                {
                    "name": "Test-Device-2",
                    "role__slug": "test-role2",
                    "platform__slug": None,
                    "primary_ip__address": None,
                    "tags": ["test-tag"],
                    "cf__fqdn": None,
                },
                {
                    "name": "Test-Device-3",
                    "role__slug": "test-role2",
                    "platform__slug": None,
                    "primary_ip__address": "2001:db8::dead:beef:1/64",
                    "tags": [],
                    "cf__fqdn": None,
                },
                {
                    "name": None,
                    "role__slug": "test-role2",
                    "platform__slug": None,
                    "primary_ip__address": None,
                    "tags": [],
                    "cf__fqdn": None,
                },
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms-attrs/",
            [
                {
                    "name": "VM1",
                    "role__slug": "test-role",
                    "platform__slug": None,
                    "primary_ip__address": "2001:db8::3/128",
                    "tags": ["test-tag"],
                    "cf__fqdn": "vm-1.example.com",
                },
                {
                    "name": "VM2",
                    "role__slug": "test-role2",
                    "platform__slug": None,
                    "primary_ip__address": None,
                    "tags": [],
                    "cf__fqdn": None,
                },
                {
                    "name": "Test Device 1",
                    "role__slug": "test-role",
                    "platform__slug": None,
                    "primary_ip__address": "2001:db8::1/128",
                    "tags": ["test-device-tag"],
                    "cf__fqdn": "device-1.example.com",
                },
                {
                    "name": "Test-Device-2",
                    "role__slug": "test-role2",
                    "platform__slug": None,
                    "primary_ip__address": None,
                    "tags": ["test-tag"],
                    "cf__fqdn": None,
                },
                {
                    "name": "Test-Device-3",
                    "role__slug": "test-role2",
                    "platform__slug": None,
                    "primary_ip__address": "2001:db8::dead:beef:1/64",
                    "tags": [],
                    "cf__fqdn": None,
                },
                {
                    "name": None,
                    "role__slug": "test-role2",
                    "platform__slug": None,
                    "primary_ip__address": None,
                    "tags": [],
                    "cf__fqdn": None,
                },
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms-attrs/?name=VM2",
            [
                {
                    "name": "VM2",
                    "role__slug": "test-role2",
                    "platform__slug": None,
                    "primary_ip__address": None,
                    "tags": [],
                    "cf__fqdn": None,
                }
            ],
        ),
        (
            "http://localhost:8000/api/plugins/lists/devices-vms-attrs/?cf_fqdn=example.com",
            [
                {
                    "name": "VM1",
                    "role__slug": "test-role",
                    "platform__slug": None,
                    "primary_ip__address": "2001:db8::3/128",
                    "tags": ["test-tag"],
                    "cf__fqdn": "vm-1.example.com",
                },
                {
                    "name": "Test Device 1",
                    "role__slug": "test-role",
                    "platform__slug": None,
                    "primary_ip__address": "2001:db8::1/128",
                    "tags": ["test-device-tag"],
                    "cf__fqdn": "device-1.example.com",
                },
            ],
        ),
    ],
)
def test_devices_vms_attrs(
    nb_api: pynetbox.api,
    nb_requests: requests.Session,
    url: str,
    expected: list[dict[str, Any]],
) -> None:
    resp = nb_requests.get(url)
    assert resp.status_code == 200
    assert resp.headers["Content-Type"] == "application/json"

    resp_json = resp.json()
    assert isinstance(resp_json, list)
    assert len(resp_json) == len(expected)

    for device in resp_json:
        device.pop("id", None)

    assert resp_json == expected


def test_devices_vms_attrs_invalid_filter(
    nb_api: pynetbox.api,
    nb_requests: requests.Session,
) -> None:
    resp = nb_requests.get(
        "http://localhost:8000/api/plugins/lists/devices-vms-attrs/?role=invalid-role"
    )
    assert resp.status_code == 400
    assert resp.headers["Content-Type"] == "application/json"


@pytest.mark.parametrize(
    "url",
    (
        "http://localhost:8000/api/plugins/lists/devices-vms/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/prefixes/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/aggregates/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/services/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/devices/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/virtual-machines/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/ip-addresses/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/ip-ranges/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/prometheus-devices/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/prometheus-vms/?invalid_filter=test",
        "http://localhost:8000/api/plugins/lists/tags/test-tag?invalid_param",
    ),
)
def test_devices_vms_invalid_filter(
    nb_api: pynetbox.api,
    nb_requests: requests.Session,
    url: str,
) -> None:
    resp = nb_requests.get(url)
    assert resp.status_code == 400
    assert resp.headers["Content-Type"] == "application/json"


def test_devices_vms_invalid_filter_option(
    nb_api: pynetbox.api,
    nb_requests: requests.Session,
) -> None:
    resp = nb_requests.get(
        "http://localhost:8000/api/plugins/lists/devices-vms/?role=invalid-role"
    )
    assert resp.status_code == 400
    assert resp.headers["Content-Type"] == "application/json"


def test_tags_404(nb_api: pynetbox.api, nb_requests: requests.Session):
    resp = nb_requests.get("http://localhost:8000/api/plugins/lists/bad-tag/?ips")
    assert resp.status_code == 404


def test_openapi(nb_requests: requests.Session):
    # nb_api.openapi()

    resp = nb_requests.get("http://localhost:8000/api/schema/")
    assert resp.ok


def test_lists_api_root_urls_unique(nb_requests: requests.Session):
    resp = nb_requests.get("http://localhost:8000/api/plugins/lists/")
    assert resp.ok

    d = resp.json()
    assert isinstance(d, dict)

    unique_d = {}
    for k, v in d.items():
        if v not in unique_d.values():
            unique_d[k] = v

    assert unique_d == d
