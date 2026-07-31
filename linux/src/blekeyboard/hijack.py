import socket

from blekeyboard.hci import (
    HCI_COMMAND_PKT,
    LE_MIN_ACL_PAYLOAD,
    build_acl,
    fragment_payload,
)

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

        # Replaced by the controller's reported capacity once LE Read Buffer
        # Size has been answered. Until then, assume the LE minimum every
        # controller is required to accept.
        self.max_acl_payload = LE_MIN_ACL_PAYLOAD

        # Controller buffer slots available for outbound ACL data. Sending
        # more than the controller can hold overruns it, so transmission is
        # gated on these credits and they are returned by the
        # Number Of Completed Packets event.
        self.total_acl_credits = 0
        self.available_acl_credits = 0

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

    def configure_acl_buffers(self, payload_length: int, total_packets: int):
        """Adopts the ACL capacity the controller reported."""
        if payload_length > 0:
            self.max_acl_payload = payload_length
        self.total_acl_credits = total_packets
        self.available_acl_credits = total_packets

    def credit_acl_packets(self, count: int):
        """Returns buffer slots released by a Number Of Completed Packets event."""
        self.available_acl_credits = min(
            self.total_acl_credits,
            self.available_acl_credits + count,
        )

    def send_control_packet(self, packet: list[int]):
        """Writes an HCI command packet to the controller, framed with the H4 command indicator."""
        if not self.sock:
            raise RuntimeError("Cannot transmit: transport session is not established.")
        self.sock.send(bytes([HCI_COMMAND_PKT] + packet))

    def send_acl_payload(self, handle: int, payload: bytes) -> int:
        """
        Writes a payload to a connection, splitting it across ACL packets.

        Returns the number of ACL packets sent. Raises RuntimeError if the
        controller has no free buffer slots, since overrunning them is a
        protocol violation rather than something to retry blindly.
        """
        if not self.sock:
            raise RuntimeError("Cannot transmit: transport session is not established.")

        fragments = fragment_payload(bytes(payload), self.max_acl_payload)

        # Only enforce credits once the controller has told us its capacity.
        if self.total_acl_credits and len(fragments) > self.available_acl_credits:
            raise RuntimeError(
                f"Controller has {self.available_acl_credits} ACL buffer(s) free, "
                f"but {len(fragments)} are needed."
            )

        for boundary, fragment in fragments:
            self.sock.send(build_acl(handle, boundary, fragment))
            if self.total_acl_credits:
                self.available_acl_credits -= 1

        return len(fragments)

    def read_packet(self, timeout_ms: int = 1000) -> list[int]:
        """Reads one raw HCI packet from the controller, of any type."""
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
