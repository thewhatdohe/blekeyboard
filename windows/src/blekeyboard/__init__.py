"""
Windows implementation of `blekeyboard`.

Not yet functional. The transport layer - raw USB access to the Bluetooth
controller via WinUSB/libusb, bypassing the vendor driver - exists and is
tested (see `USBTransport` in `blekeyboard.hijack`), but the protocol layers
above it - L2CAP, ATT/GATT, SMP pairing, HID report delivery - do not exist
in this package yet. `Keyboard` is a placeholder so that code written
against the Linux package's API fails with a clear explanation instead of a
bare ImportError.

See https://github.com/thewhatdohe/blekeyboard for the working Linux
implementation and current project status.
"""

_NOT_IMPLEMENTED = (
    "Windows support is not implemented yet: the USB transport layer exists, "
    "but pairing, GATT, and HID report delivery do not. See "
    "https://github.com/thewhatdohe/blekeyboard for the working Linux "
    "implementation and current status."
)


class Keyboard:
    """Placeholder matching the Linux package's public API. Not usable yet."""

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(_NOT_IMPLEMENTED)


__all__ = ["Keyboard"]
