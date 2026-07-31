import socket

from blekeyboard.hci import HCI_ACLDATA_PKT, HCI_COMMAND_PKT, HCI_EVENT_PKT

# BlueZ HCI user channel: hands a controller over for exclusive raw HCI
# access, bypassing bluetoothd/the kernel Bluetooth stack. This is the
# native Linux equivalent of swapping the Windows driver to WinUSB.
HCI_CHANNEL_USER = 1

# Large enough for any LE packet the controller can hand back, including an
# ACL payload extended to the 251-octet maximum plus its framing.
_RECV_BUFFER_SIZE = 4096


class HCITransport:
    """
    Manages a raw HCI transport to a local Bluetooth controller.
    """

    def __init__(self, dev_id: int = 0):
        self.dev_id = dev_id
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
                f"Ensure the adapter is down (sudo btmgmt --index {self.dev_id} power off) "
                f"and this process has CAP_NET_ADMIN (e.g. run as root). ({e})"
            )
        self.sock = sock

    def send_control_packet(self, packet: list[int]):
        """Writes an HCI command packet to the controller, framed with the H4 command indicator."""
        if not self.sock:
            raise RuntimeError("Cannot transmit: transport session is not established.")
        self.sock.send(bytes([HCI_COMMAND_PKT] + packet))

    def read_event_packet(self, timeout_ms: int = 1000) -> list[int]:
        """Reads one raw HCI packet from the controller."""
        if not self.sock:
            raise RuntimeError("Cannot receive: transport session is not established.")
        self.sock.settimeout(timeout_ms / 1000)
        try:
            raw_data = self.sock.recv(_RECV_BUFFER_SIZE)
        except OSError as e:
            # Socket timeout (no data ready) is normal and not an error.
            if isinstance(e, TimeoutError) or "timed out" in str(e).lower():
                return []
            raise

        return list(raw_data)

    def release(self):
        """Closes the raw HCI socket, returning the adapter to the kernel Bluetooth stack."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
