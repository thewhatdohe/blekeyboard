import sys
import time

from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.hci import (
    ROLE_PERIPHERAL,
    ACLData,
    CommandComplete,
    ConnectionComplete,
    DisconnectionComplete,
    NumberOfCompletedPackets,
    parse_acl,
    parse_event,
    parse_le_buffer_size,
)
from blekeyboard.hijack import HCITransport
from blekeyboard.l2cap import L2CAPReassembler

DEVICE_NAME = "BLE-Ducky"
KEEPALIVE_INTERVAL_SECONDS = 10.0
OPCODE_LE_READ_BUFFER_SIZE = 0x2002


def main():
    print("Starting blekeyboard emulator service...")

    # Target hardware device context: local Bluetooth adapter hci0.
    transport = HCITransport(dev_id=0)
    broadcaster = BLEBroadcaster(transport)
    session = _Session(transport, broadcaster)
    exit_code = 0

    try:
        transport.connect()

        # A freshly claimed controller is uninitialized, so reset it before
        # configuring anything else.
        broadcaster.reset_controller()
        time.sleep(0.1)

        # The reset default masks off LE Meta events, so connection events
        # would never reach us without this.
        broadcaster.set_event_mask()
        broadcaster.set_le_event_mask()
        time.sleep(0.1)

        # Learn the controller's ACL capacity before any data is exchanged.
        broadcaster.read_le_buffer_size()
        time.sleep(0.1)

        broadcaster.configure_advertising(interval_ms=400)
        time.sleep(0.1)

        broadcaster.set_advertising_payload(DEVICE_NAME)
        time.sleep(0.1)

        broadcaster.set_state(enable=True)
        print(f"Advertising as '{DEVICE_NAME}'.")
        print("Press Ctrl+C to stop.")

        last_keepalive = time.time()

        while True:
            # The read timeout paces the loop, so no additional sleep is needed.
            session.handle(transport.read_packet(timeout_ms=200))

            if time.time() - last_keepalive >= KEEPALIVE_INTERVAL_SECONDS:
                broadcaster.send_keepalive_ping()
                last_keepalive = time.time()

    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"\nFatal error: {e}")
        exit_code = 1
    finally:
        # The transport may never have been established, in which case there is
        # nothing to wind down and set_state would raise over the real error.
        try:
            broadcaster.set_state(enable=False)
        except RuntimeError:
            pass
        transport.release()
        print("Hardware interfaces released.")

    return exit_code


class _Session:
    """Tracks live connections and the L2CAP traffic arriving on them."""

    def __init__(self, transport, broadcaster):
        self._transport = transport
        self._broadcaster = broadcaster
        self._peers = {}
        self._reassemblers = {}

    def handle(self, packet):
        """Routes one raw HCI packet to the appropriate handler."""
        if not packet:
            return

        acl = parse_acl(packet)
        if acl is not None:
            self._handle_acl(acl)
            return

        event = parse_event(packet)
        if isinstance(event, ConnectionComplete):
            self._handle_connection(event)
        elif isinstance(event, DisconnectionComplete):
            self._handle_disconnection(event)
        elif isinstance(event, NumberOfCompletedPackets):
            for _handle, count in event.counts:
                self._transport.credit_acl_packets(count)
        elif isinstance(event, CommandComplete):
            self._handle_command_complete(event)

    def _handle_command_complete(self, event):
        if event.opcode != OPCODE_LE_READ_BUFFER_SIZE:
            return

        capacity = parse_le_buffer_size(event.parameters)
        if capacity is None:
            print("Controller did not report LE buffer capacity; using defaults.")
            return

        payload_length, total_packets = capacity
        self._transport.configure_acl_buffers(payload_length, total_packets)
        print(
            f"Controller ACL capacity: {self._transport.max_acl_payload} byte payload, "
            f"{total_packets} buffer(s)."
        )

    def _handle_connection(self, event):
        if event.status != 0x00:
            print(f"Connection failed with status 0x{event.status:02X}.")
            self._broadcaster.set_state(enable=True)
            return

        self._peers[event.handle] = event.peer_address
        self._reassemblers[event.handle] = L2CAPReassembler()
        role = "peripheral" if event.role == ROLE_PERIPHERAL else "central"
        print(f"Connected to {event.peer_address} as {role}, handle 0x{event.handle:04X}.")

    def _handle_disconnection(self, event):
        peer = self._peers.pop(event.handle, "unknown peer")
        self._reassemblers.pop(event.handle, None)
        print(f"Disconnected from {peer}, reason 0x{event.reason:02X}.")

        # The controller stops advertising once a connection is established,
        # so it has to be re-enabled to become discoverable again.
        self._broadcaster.set_state(enable=True)
        print(f"Advertising as '{DEVICE_NAME}' again.")

    def _handle_acl(self, acl):
        reassembler = self._reassemblers.get(acl.handle)
        if reassembler is None:
            print(f"ACL data on unknown handle 0x{acl.handle:04X}; ignoring.")
            return

        for frame in reassembler.feed(acl.packet_boundary, acl.data):
            preview = " ".join(f"{b:02X}" for b in frame.payload[:8])
            if len(frame.payload) > 8:
                preview += " ..."
            print(
                f"  {frame.channel_name}: {len(frame.payload)} byte(s) [{preview}]"
            )


if __name__ == "__main__":
    sys.exit(main())
