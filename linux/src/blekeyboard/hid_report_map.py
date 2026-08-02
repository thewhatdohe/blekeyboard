"""
The HID report descriptor advertised through the Report Map characteristic.

This is a standard USB HID keyboard descriptor: an 8-byte input report
(modifier byte, a reserved byte, six simultaneous keycodes) under Report ID
1, plus the matching 1-byte LED output report a host uses to reflect
Caps/Num/Scroll Lock state. A host parses this once at discovery time to
learn the shape of the reports that follow; nothing about it is BLE-specific.

Report ID 1 is included even though only one report is defined, so a second
report (for example, consumer control / media keys) can be added later
without changing this one's framing.
"""

KEYBOARD_REPORT_ID = 1

REPORT_MAP = bytes([
    0x05, 0x01,        # Usage Page (Generic Desktop)
    0x09, 0x06,        # Usage (Keyboard)
    0xA1, 0x01,        # Collection (Application)
    0x85, KEYBOARD_REPORT_ID,  #   Report ID (1)

    0x05, 0x07,        #   Usage Page (Keyboard/Keypad)
    0x19, 0xE0,        #   Usage Minimum (224, Left Control)
    0x29, 0xE7,        #   Usage Maximum (231, Right GUI)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x01,        #   Logical Maximum (1)
    0x75, 0x01,        #   Report Size (1 bit)
    0x95, 0x08,        #   Report Count (8) -> the modifier byte
    0x81, 0x02,        #   Input (Data, Variable, Absolute)

    0x95, 0x01,        #   Report Count (1)
    0x75, 0x08,        #   Report Size (8 bits)
    0x81, 0x01,        #   Input (Constant) -> reserved byte

    0x95, 0x05,        #   Report Count (5)
    0x75, 0x01,        #   Report Size (1 bit)
    0x05, 0x08,        #   Usage Page (LEDs)
    0x19, 0x01,        #   Usage Minimum (Num Lock)
    0x29, 0x05,        #   Usage Maximum (Kana)
    0x91, 0x02,        #   Output (Data, Variable, Absolute) -> LED report

    0x95, 0x01,        #   Report Count (1)
    0x75, 0x03,        #   Report Size (3 bits)
    0x91, 0x01,        #   Output (Constant) -> LED report padding

    0x95, 0x06,        #   Report Count (6) -> up to six simultaneous keys
    0x75, 0x08,        #   Report Size (8 bits)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x65,        #   Logical Maximum (101)
    0x05, 0x07,        #   Usage Page (Keyboard/Keypad)
    0x19, 0x00,        #   Usage Minimum (0, no key)
    0x29, 0x65,        #   Usage Maximum (101)
    0x81, 0x00,        #   Input (Data, Array)

    0xC0,              # End Collection
])

# Bytes of one input report on the wire: the Report ID byte the descriptor's
# Report ID tag requires, the modifier byte, a reserved byte, and up to six
# keycodes.
INPUT_REPORT_LENGTH = 9

# LED states a host may write in the output report, one bit each.
LED_NUM_LOCK = 0x01
LED_CAPS_LOCK = 0x02
LED_SCROLL_LOCK = 0x04
LED_COMPOSE = 0x08
LED_KANA = 0x10

# The report's key array holds at most six simultaneously pressed keys, per
# the Report Count (6) in the descriptor above.
MAX_SIMULTANEOUS_KEYS = 6


def build_input_report(modifier: int = 0, keycodes=()) -> bytes:
    """
    Builds one input report: the Report ID, the modifier byte, a reserved
    byte, and up to six keycodes padded with zero (no key) to fill the array.

    An empty `keycodes` with modifier 0 is the all-zero "nothing pressed"
    report a key release sends.
    """
    if len(keycodes) > MAX_SIMULTANEOUS_KEYS:
        raise ValueError(
            f"At most {MAX_SIMULTANEOUS_KEYS} simultaneous keys are representable, "
            f"got {len(keycodes)}."
        )

    padded = bytes(keycodes) + bytes(MAX_SIMULTANEOUS_KEYS - len(keycodes))
    return bytes([KEYBOARD_REPORT_ID, modifier, 0x00]) + padded
