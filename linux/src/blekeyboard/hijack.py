import socket

# BlueZ HCI user channel: hands a controller over for exclusive raw HCI
# access, bypassing bluetoothd/the kernel Bluetooth stack. This is the
# native Linux equivalent of swapping the Windows driver to WinUSB.
HCI_CHANNEL_USER = 1

# H4 UART framing packet type indicators used on raw HCI sockets.
HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT = 0x04

# Command Complete event code, and the opcode for "Read RSSI" (OGF 0x05 / OCF 0x0005),
# used to opportunistically keep _last_rssi fresh whenever an event is read.
_EVT_CMD_COMPLETE = 0x0E
_OPCODE_READ_RSSI = (0x05 << 10) | 0x0005


class HCITransport:
    """
    Manages a raw HCI transport to a local Bluetooth controller.
    """

    def __init__(self, dev_id: int = 0):
        self.dev_id = dev_id
        self._last_rssi = -127  # Lowest strength possible (basically off)
        self.sock = None

    def connect(self):
        """Opens a raw HCI socket and claims exclusive (user channel) access to the adapter."""
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        try:
            sock.bind((self.dev_id, HCI_CHANNEL_USER))
        except OSError as e:
            sock.close()
            raise RuntimeError(
                f"Failed to claim hci{self.dev_id} as a user channel. "
                f"Ensure the adapter is down (sudo hciconfig hci{self.dev_id} down) "
                f"and this process has CAP_NET_ADMIN (e.g. run as root). ({e})"
            )
        self.sock = sock

    def get_last_rssi(self) -> int:
        """Returns the most recently captured raw RSSI value."""
        return self._last_rssi

    def send_control_packet(self, packet: list[int]):
        """Writes an HCI command packet to the controller, framed with the H4 command indicator."""
        if not self.sock:
            raise RuntimeError("Cannot transmit: transport session is not established.")
        self.sock.send(bytes([HCI_COMMAND_PKT] + packet))

    def read_event_packet(self, timeout_ms: int = 1000) -> list[int]:
        """Reads a raw HCI event packet from the controller."""
        if not self.sock:
            raise RuntimeError("Cannot receive: transport session is not established.")
        self.sock.settimeout(timeout_ms / 1000)
        try:
            raw_data = self.sock.recv(255)
        except OSError as e:
            # Socket timeout (no data ready) is normal and not an error.
            if isinstance(e, TimeoutError) or "timed out" in str(e).lower():
                return []
            raise

        event = list(raw_data)
        self._maybe_capture_rssi(event)
        return event

    def _maybe_capture_rssi(self, event: list[int]):
        """Updates _last_rssi if the event is a successful Read RSSI Command Complete."""
        if len(event) < 10 or event[0] != HCI_EVENT_PKT or event[1] != _EVT_CMD_COMPLETE:
            return
        opcode = event[4] | (event[5] << 8)
        status = event[6]
        if opcode != _OPCODE_READ_RSSI or status != 0x00:
            return
        rssi_byte = event[9]
        self._last_rssi = rssi_byte - 256 if rssi_byte > 127 else rssi_byte

    def release(self):
        """Closes the raw HCI socket, returning the adapter to the kernel Bluetooth stack."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
