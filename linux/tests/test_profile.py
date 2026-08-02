from blekeyboard.gatt import UUID_CHARACTERISTIC, UUID_CLIENT_CHARACTERISTIC_CONFIGURATION
from blekeyboard.hid_report_map import KEYBOARD_REPORT_ID, REPORT_MAP
from blekeyboard.profile import (
    APPEARANCE_KEYBOARD,
    REPORT_TYPE_INPUT,
    UUID_APPEARANCE,
    UUID_BATTERY_LEVEL,
    UUID_BATTERY_SERVICE,
    UUID_DEVICE_INFORMATION_SERVICE,
    UUID_DEVICE_NAME,
    UUID_GAP_SERVICE,
    UUID_GATT_SERVICE,
    UUID_HID_CONTROL_POINT,
    UUID_HID_INFORMATION,
    UUID_HID_SERVICE,
    UUID_PNP_ID,
    UUID_PROTOCOL_MODE,
    UUID_REPORT,
    UUID_REPORT_MAP,
    build_database,
)


def find(database, uuid):
    for attribute in database.attributes:
        if attribute.uuid == uuid:
            return attribute
    raise AssertionError(f"no attribute with UUID {uuid!r}")


class TestServiceOrder:
    def test_services_appear_in_declared_order(self):
        database, _ = build_database("BLE-Ducky")
        # A service declaration's own UUID is just the 0x2800 marker; the
        # service it names is carried in the declaration's value.
        services = [int.from_bytes(a.value, "little") for a in database.attributes
                    if a.uuid == 0x2800]
        assert services == [
            UUID_GAP_SERVICE, UUID_GATT_SERVICE,
            UUID_DEVICE_INFORMATION_SERVICE, UUID_BATTERY_SERVICE,
            UUID_HID_SERVICE,
        ]


class TestGenericAccess:
    def test_device_name_carries_the_requested_name(self):
        database, _ = build_database("BLE-Ducky")
        assert find(database, UUID_DEVICE_NAME).value == b"BLE-Ducky"

    def test_appearance_identifies_a_keyboard(self):
        database, _ = build_database("BLE-Ducky")
        value = find(database, UUID_APPEARANCE).value
        assert int.from_bytes(value, "little") == APPEARANCE_KEYBOARD


class TestDeviceInformation:
    def test_pnp_id_is_seven_octets(self):
        database, _ = build_database("BLE-Ducky")
        assert len(find(database, UUID_PNP_ID).value) == 7

    def test_pnp_id_declares_a_usb_if_vendor_id_source(self):
        database, _ = build_database("BLE-Ducky")
        assert find(database, UUID_PNP_ID).value[0] == 0x02


class TestBatteryService:
    def test_level_is_a_single_percentage_byte(self):
        database, _ = build_database("BLE-Ducky")
        level = find(database, UUID_BATTERY_LEVEL)
        assert len(level.value) == 1
        assert 0 <= level.value[0] <= 100

    def test_level_has_a_notification_descriptor(self):
        database, _ = build_database("BLE-Ducky")
        level = find(database, UUID_BATTERY_LEVEL)
        cccd = database.find(level.handle + 1)
        assert cccd.uuid == UUID_CLIENT_CHARACTERISTIC_CONFIGURATION


class TestHidService:
    def test_hid_information_is_four_octets(self):
        database, _ = build_database("BLE-Ducky")
        assert len(find(database, UUID_HID_INFORMATION).value) == 4

    def test_report_map_matches_the_declared_descriptor(self):
        database, _ = build_database("BLE-Ducky")
        assert find(database, UUID_REPORT_MAP).value == REPORT_MAP

    def test_control_point_is_write_only(self):
        database, _ = build_database("BLE-Ducky")
        control_point = find(database, UUID_HID_CONTROL_POINT)
        assert control_point.writable
        assert not control_point.readable

    def test_protocol_mode_defaults_to_report_protocol(self):
        database, _ = build_database("BLE-Ducky")
        assert find(database, UUID_PROTOCOL_MODE).value == bytes([0x01])

    def test_input_report_requires_encryption(self):
        database, _ = build_database("BLE-Ducky")
        report = find(database, UUID_REPORT)
        assert report.requires_encryption

    def test_input_report_is_not_writable(self):
        database, _ = build_database("BLE-Ducky")
        assert not find(database, UUID_REPORT).writable

    def test_input_report_has_a_report_reference_naming_it_as_input(self):
        database, _ = build_database("BLE-Ducky")
        report = find(database, UUID_REPORT)

        # The Report Reference descriptor follows the CCCD, which follows
        # the value attribute.
        reference = database.find(report.handle + 2)
        assert reference is not None
        assert reference.value == bytes([KEYBOARD_REPORT_ID, REPORT_TYPE_INPUT])

    def test_returned_attribute_is_the_input_report(self):
        database, report = build_database("BLE-Ducky")
        assert report.uuid == UUID_REPORT
        assert database.find(report.handle) is report
