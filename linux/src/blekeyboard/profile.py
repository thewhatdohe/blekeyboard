"""
The attribute table this peripheral exposes.

Generic Access and Generic Attribute, which every LE peripheral publishes,
plus the three services HID over GATT requires of a keyboard: HID, Battery,
and Device Information.
"""

from blekeyboard.gatt import (
    PROP_NOTIFY,
    PROP_READ,
    PROP_WRITE,
    PROP_WRITE_WITHOUT_RESPONSE,
    UUID_CLIENT_CHARACTERISTIC_CONFIGURATION,
    UUID_REPORT_REFERENCE,
    AttributeDatabase,
)
from blekeyboard.hid_report_map import KEYBOARD_REPORT_ID, REPORT_MAP

# Service UUIDs assigned by the Bluetooth SIG.
UUID_GAP_SERVICE = 0x1800
UUID_GATT_SERVICE = 0x1801
UUID_DEVICE_INFORMATION_SERVICE = 0x180A
UUID_BATTERY_SERVICE = 0x180F
UUID_HID_SERVICE = 0x1812

# Characteristics of the GAP service.
UUID_DEVICE_NAME = 0x2A00
UUID_APPEARANCE = 0x2A01

# Characteristics of the Device Information service.
UUID_PNP_ID = 0x2A50

# Characteristics of the Battery service.
UUID_BATTERY_LEVEL = 0x2A19

# Characteristics of the HID service.
UUID_HID_INFORMATION = 0x2A4A
UUID_REPORT_MAP = 0x2A4B
UUID_HID_CONTROL_POINT = 0x2A4C
UUID_REPORT = 0x2A4D
UUID_PROTOCOL_MODE = 0x2A4E

# Appearance value describing a keyboard, which lets a host show a sensible
# icon and category before any service discovery has happened.
APPEARANCE_KEYBOARD = 0x03C1

# Values a client may write to Protocol Mode; Boot Protocol Mode is not
# implemented, so it is not accepted.
PROTOCOL_MODE_REPORT = 0x01

# Values a client may write to HID Control Point.
HID_CONTROL_POINT_SUSPEND = 0x00
HID_CONTROL_POINT_EXIT_SUSPEND = 0x01

# Report Reference values: which report this is, and that it is an input
# report rather than output or feature.
REPORT_TYPE_INPUT = 0x01


def build_database(device_name: str):
    """
    Builds the attribute table for a peripheral advertising the given name.

    Returns the database and the input report attribute, since sending a
    keystroke means notifying that attribute directly rather than going
    through the request/response path the rest of the server handles.
    """
    database = AttributeDatabase()
    _add_generic_access(database, device_name)
    _add_generic_attribute(database)
    _add_device_information(database)
    _add_battery_service(database)
    input_report = _add_hid_service(database)
    return database, input_report


def _add_generic_access(database: AttributeDatabase, device_name: str):
    database.add_service(UUID_GAP_SERVICE)
    database.add_characteristic(
        UUID_DEVICE_NAME, PROP_READ, device_name.encode("utf-8"),
    )
    database.add_characteristic(
        UUID_APPEARANCE, PROP_READ, APPEARANCE_KEYBOARD.to_bytes(2, "little"),
    )


def _add_generic_attribute(database: AttributeDatabase):
    # Declared so a client can see the service exists, even though there is
    # nothing to notify about yet.
    database.add_service(UUID_GATT_SERVICE)


def _add_device_information(database: AttributeDatabase):
    database.add_service(UUID_DEVICE_INFORMATION_SERVICE)

    # PnP ID is the one mandatory characteristic of this service. Vendor ID
    # source 0x02 marks the following vendor ID as USB-IF assigned; 0xFFFF is
    # the placeholder used by devices without a registered USB vendor ID.
    pnp_id = bytes([0x02]) + (0xFFFF).to_bytes(2, "little") \
        + (0x0001).to_bytes(2, "little") + (0x0001).to_bytes(2, "little")
    database.add_characteristic(UUID_PNP_ID, PROP_READ, pnp_id)


def _add_battery_service(database: AttributeDatabase):
    database.add_service(UUID_BATTERY_SERVICE)
    _, level = database.add_characteristic(
        UUID_BATTERY_LEVEL, PROP_READ | PROP_NOTIFY, bytes([100]),
    )
    database.add_descriptor(
        UUID_CLIENT_CHARACTERISTIC_CONFIGURATION, b"\x00\x00", writable=True,
    )
    return level


def _add_hid_service(database: AttributeDatabase):
    database.add_service(UUID_HID_SERVICE)

    # HID Information: HID spec version 1.11, no country code, and flags
    # indicating the device is normally connectable and does not need a
    # dedicated remote wake capability.
    database.add_characteristic(
        UUID_HID_INFORMATION, PROP_READ,
        bytes([0x11, 0x01, 0x00, 0x02]),
    )

    # iOS in particular declines to treat the peripheral as a real HID
    # device unless this is only readable once the link is encrypted, even
    # though the HOGP spec itself does not strictly require it here.
    database.add_characteristic(
        UUID_REPORT_MAP, PROP_READ, REPORT_MAP, requires_encryption=True,
    )

    database.add_characteristic(UUID_HID_CONTROL_POINT, PROP_WRITE_WITHOUT_RESPONSE)

    database.add_characteristic(
        UUID_PROTOCOL_MODE, PROP_READ | PROP_WRITE_WITHOUT_RESPONSE,
        bytes([PROTOCOL_MODE_REPORT]),
    )

    # The input report itself. Reading requires encryption because HOGP
    # mandates a secured link before a host may exchange reports; writing
    # is not offered since a keyboard has no legitimate input report to
    # receive.
    _, report = database.add_characteristic(
        UUID_REPORT, PROP_READ | PROP_NOTIFY,
        bytes(9), requires_encryption=True,
    )
    database.add_descriptor(
        UUID_CLIENT_CHARACTERISTIC_CONFIGURATION, b"\x00\x00", writable=True,
    )
    database.add_descriptor(
        UUID_REPORT_REFERENCE,
        bytes([KEYBOARD_REPORT_ID, REPORT_TYPE_INPUT]),
        requires_encryption=True,
    )

    return report
