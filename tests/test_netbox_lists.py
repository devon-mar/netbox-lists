from typing import List
import requests
import pynetbox
from pynetbox.core import endpoint, response
import pytest

nb_objects: List[response.Record] = []


def nb_cleanup():
    nb_objects.reverse()
    for obj in nb_objects:
        try:
            obj.delete()
        except Exception as e:
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


@pytest.fixture(scope="session")
def nb_requests():
    s = requests.session()
    s.headers["Authorization"] = "Token 0123456789abcdef0123456789abcdef01234567"
    s.headers["Accept"] = "application/json"
    return s


@pytest.fixture(scope="session")
def nb_api():
    api = pynetbox.api(
        "http://localhost:8000",
        token="0123456789abcdef0123456789abcdef01234567"
    )

    test_tag = nb_create(
        api.extras.tags,
        name="Test Tag",
        slug="test-tag"
    )
    test_device_tag = nb_create(
        api.extras.tags,
        name="Test Device Tag",
        slug="test-device-tag"
    )
    test_site = nb_create(
        api.dcim.sites,
        name="Test Site",
        slug="test-site"
    )
    test_device_role = nb_create(
        api.dcim.device_roles,
        name="Test Role",
        slug="test-role"
    )
    test_manufacturer = nb_create(
        api.dcim.manufacturers,
        name="Test Manufacturer",
        slug="test-manufacturer"
    )
    test_device_type = nb_create(
        api.dcim.device_types,
        manufacturer=test_manufacturer.id,
        model="test model",
        slug="test-model"
    )
    test_device_1 = nb_create(
        api.dcim.devices,
        name="Test Device 1",
        device_type=test_device_type.id,
        device_role=test_device_role.id,
        site=test_site.id,
        tags=[test_device_tag.id]
    )
    test_device_1_intf_1 = nb_create(
        api.dcim.interfaces,
        name="GigabitEthernet1/1",
        type="1000base-t",
        device=test_device_1.id
    )
    test_device_1_intf_1_ip_1 = nb_create(
        api.ipam.ip_addresses,
        address="192.0.2.1/24",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_1_intf_1.id
    )
    test_device_1_intf_1_ip_2 = nb_create(
        api.ipam.ip_addresses,
        address="2001:db8::1/128",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_1_intf_1.id
    )
    # Set the primary IP
    nb_update(
        test_device_1,
        {"primary_ip4": test_device_1_intf_1_ip_1.id, "primary_ip6": test_device_1_intf_1_ip_2.id}
    )

    test_device_2 = nb_create(
        api.dcim.devices,
        name="Test-Device-2",
        device_type=test_device_type.id,
        device_role=test_device_role.id,
        site=test_site.id,
        tags=[test_tag.id]
    )
    test_device_2_intf_1 = nb_create(
        api.dcim.interfaces,
        name="GigabitEthernet1/1",
        type="1000base-t",
        device=test_device_2.id
    )
    test_device_2_intf_1_ip_1 = nb_create(
        api.ipam.ip_addresses,
        address="192.0.2.2/24",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_2_intf_1.id,
        tags=[test_tag.id]
    )
    # A duplicate IP of test_device_1 but with a different prefix length.
    test_device_2_intf_1_ip_2 = nb_create(
        api.ipam.ip_addresses,
        address="2001:db8::1/127",
        assigned_object_type="dcim.interface",
        assigned_object_id=test_device_2_intf_1.id,
        tags=[test_tag.id]
    )
    test_device_2_svc_1 = nb_create(
        api.ipam.services,
        name="DNS",
        ports=[53],
        protocol="udp",
        device=test_device_2.id,
        ipaddresses=[test_device_2_intf_1_ip_1.id]
    )
    test_cluster_type = nb_create(
        api.virtualization.cluster_types,
        name="test cluster type",
        slug="test-cluster-type"
    )
    test_cluster = nb_create(
        api.virtualization.clusters,
        name="Test Cluster",
        type=test_cluster_type.id
    )
    test_vm_1 = nb_create(
        api.virtualization.virtual_machines,
        name="VM1",
        cluster=test_cluster.id,
        tags=[test_tag.id]
    )
    test_vm_1_intf_1 = nb_create(
        api.virtualization.interfaces,
        name="eth0",
        virtual_machine=test_vm_1.id
    )
    test_vm_1_intf_1_ip_1 = nb_create(
        api.ipam.ip_addresses,
        address="192.0.2.3/24",
        assigned_object_type="virtualization.vminterface",
        assigned_object_id=test_vm_1_intf_1.id
    )
    test_vm_1_intf_1_ip_2 = nb_create(
        api.ipam.ip_addresses,
        address="2001:db8::3/128",
        assigned_object_type="virtualization.vminterface",
        assigned_object_id=test_vm_1_intf_1.id
    )
    # Set primary IP for VM1
    nb_update(test_vm_1, {"primary_ip4": test_vm_1_intf_1_ip_1.id, "primary_ip6": test_vm_1_intf_1_ip_2.id})

    test_vm_2 = nb_create(
        api.virtualization.virtual_machines,
        name="VM2",
        cluster=test_cluster.id
    )

    test_prefix = nb_create(api.ipam.prefixes, prefix="192.0.2.0/24")
    test_prefix = nb_create(api.ipam.prefixes, prefix="192.0.2.32/27", tags=[test_tag.id])
    test_rir = nb_create(api.ipam.rirs, name="test rir", slug="test-rir")
    test_aggregate = nb_create(api.ipam.aggregates, prefix="10.0.0.0/8", rir=test_rir.id)
    test_aggregate = nb_create(api.ipam.aggregates, prefix="172.16.0.0/12", rir=test_rir.id, tags=[test_tag.id])

    yield api
    nb_cleanup()


@pytest.mark.parametrize(
    "url,expected",
    [
        #
        # IP Address Test Cases
        #
        (
            "http://localhost:8000/api/plugins/lists/ip-addresses",
            ["192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::3"]
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-addresses?as_cidr",
            ["192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32", "2001:db8::1/128", "2001:db8::3/128"]
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-addresses?family=4",
            ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        ),
        (
            "http://localhost:8000/api/plugins/lists/ip-addresses?family=4&as_cidr",
            ["192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"]
        ),
        ("http://localhost:8000/api/plugins/lists/prefixes", ["192.0.2.0/24", "192.0.2.32/27"]),
        ("http://localhost:8000/api/plugins/lists/aggregates", ["10.0.0.0/8", "172.16.0.0/12"]),
        ("http://localhost:8000/api/plugins/lists/services", ["192.0.2.2"]),
        ("http://localhost:8000/api/plugins/lists/services?as_cidr", ["192.0.2.2/32"]),
        #
        # Devices
        #
        ("http://localhost:8000/api/plugins/lists/devices", ["192.0.2.1", "2001:db8::1"]),
        ("http://localhost:8000/api/plugins/lists/devices?as_cidr&family=4", ["192.0.2.1/32"]),
        ("http://localhost:8000/api/plugins/lists/devices?family=6", ["2001:db8::1"]),
        #
        # Virtual Machines
        #
        ("http://localhost:8000/api/plugins/lists/virtual-machines", ["192.0.2.3", "2001:db8::3"]),
        ("http://localhost:8000/api/plugins/lists/virtual-machines?family=4", ["192.0.2.3"]),
        ("http://localhost:8000/api/plugins/lists/virtual-machines?as_cidr&family=6", ["2001:db8::3/128"]),

        # Test a tag containing only devices
        ("http://localhost:8000/api/plugins/lists/tags/test-device-tag?devices", ["192.0.2.1/32", "2001:db8::1/128"]),
        ("http://localhost:8000/api/plugins/lists/tags/test-device-tag?ips&aggregates&vms", []),
        ("http://localhost:8000/api/plugins/lists/tags/test-device-tag?devices_primary", ["192.0.2.1/32", "2001:db8::1/128"]),
        ("http://localhost:8000/api/plugins/lists/tags/test-device-tag?devices_primary&family=4", ["192.0.2.1/32"]),
        # IPs should be returned as /32s or /128s
        ("http://localhost:8000/api/plugins/lists/tags/test-tag?ips", ["192.0.2.2/32", "2001:db8::1/128"]),
        ("http://localhost:8000/api/plugins/lists/tags/test-tag?aggregates", ["172.16.0.0/12"]),
        ("http://localhost:8000/api/plugins/lists/tags/test-tag?prefixes", ["192.0.2.32/27"]),
        ("http://localhost:8000/api/plugins/lists/tags/test-tag?vms_primary", ["192.0.2.3/32", "2001:db8::3/128"]),
        ("http://localhost:8000/api/plugins/lists/tags/test-tag?vms_primary&family=6", ["2001:db8::3/128"]),
        (
            "http://localhost:8000/api/plugins/lists/tags/test-tag?ips&aggregates&prefixes",
            ["192.0.2.2/32", "2001:db8::1/128", "172.16.0.0/12", "192.0.2.32/27"]
        )
    ]
)
def test_lists(nb_api, nb_requests: requests.Session, url: str, expected: List[str]):
    req = nb_requests.get(url)
    assert req.status_code == 200
    resp = req.json()

    assert isinstance(resp, list)
    assert sorted(resp) == sorted(expected)


def test_lists_txt(nb_api, nb_requests: requests.Session):
    with_header = nb_requests.get(
        "http://localhost:8000/api/plugins/lists/ip-addresses",
        headers={"Accept": "text/plain"}
    )
    with_format = nb_requests.get(
        "http://localhost:8000/api/plugins/lists/ip-addresses?format=text",
        headers={"Accept": "*/*"}
    )
    assert sorted(with_header.text.splitlines()) == sorted(with_format.text.splitlines())

    assert sorted(with_header.text.splitlines()) == ["192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::3"]


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
                        "__meta_netbox_status": "active"
                    }
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
                        "__meta_netbox_status": "active"
                    }
                }
            ]
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
                        "__meta_netbox_status": "active"
                    }
                }
            ]
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
                        "__meta_netbox_primary_ip6": "2001:db8::3"
                    }
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
                        "__meta_netbox_primary_ip6": ""
                    }
                }
            ]
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
                        "__meta_netbox_primary_ip6": ""
                    }
                }
            ]
        )
    ]
)
def test_prom_sd(nb_api, nb_requests: requests.Session, url: str, expected: List[dict]):
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


def test_tags_404(nb_api, nb_requests: requests.Session):
    resp = nb_requests.get("http://localhost:8000/api/plugins/lists/bad-tag/?ips")
    assert resp.status_code == 404


def test_openapi(nb_api: pynetbox.api):
    try:
        nb_api.openapi()
    except Exception as e:
        pytest.fail(f"Unexpected exception: {repr(e)}")
