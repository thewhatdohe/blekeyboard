"""
The attribute table this peripheral exposes.

Currently the two services every LE peripheral is expected to publish. The
HID over GATT services will join them here once pairing is in place.
"""

from blekeyboard.gatt import PROP_READ, AttributeDatabase

# Service UUIDs assigned by the Bluetooth SIG.
UUID_GAP_SERVICE = 0x1800
UUID_GATT_SERVICE = 0x1801

# Characteristics of the GAP service.
UUID_DEVICE_NAME = 0x2A00
UUID_APPEARANCE = 0x2A01

# Appearance value describing a keyboard, which lets a host show a sensible
# icon and category before any service discovery has happened.
APPEARANCE_KEYBOARD = 0x03C1


def build_database(device_name: str) -> AttributeDatabase:
    """Builds the attribute table for a peripheral advertising the given name."""
    database = AttributeDatabase()

    # Generic Access holds the identity a host reads before anything else.
    database.add_service(UUID_GAP_SERVICE)
    database.add_characteristic(
        UUID_DEVICE_NAME,
        PROP_READ,
        device_name.encode("utf-8"),
    )
    database.add_characteristic(
        UUID_APPEARANCE,
        PROP_READ,
        APPEARANCE_KEYBOARD.to_bytes(2, "little"),
    )

    # Generic Attribute is declared so a client can see the service exists,
    # even though there is nothing to notify about yet.
    database.add_service(UUID_GATT_SERVICE)

    return database
