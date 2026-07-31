import sys
import time

from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.gatt import GattServer
from blekeyboard.hci import (
    ROLE_PERIPHERAL,
    CommandComplete,
    ConnectionComplete,
    DisconnectionComplete,
    EncryptionChange,
    LongTermKeyRequest,
    NumberOfCompletedPackets,
    format_address,
    parse_acl,
    parse_event,
    parse_le_buffer_size,
)
from blekeyboard.hijack import HCITransport
from blekeyboard.l2cap import CID_ATT, CID_SMP, L2CAPReassembler, build_frame
from blekeyboard.profile import build_database
from blekeyboard.smp import SecurityManager, State, security_request

DEVICE_NAME = "BLE-Ducky"
KEEPALIVE_INTERVAL_SECONDS = 10.0

OPCODE_LE_READ_BUFFER_SIZE = 0x2002
OPCODE_LE_ENCRYPT = 0x2017
OPCODE_LE_RAND = 0x2018
OPCODE_READ_BD_ADDR = 0x1009


def main():
    print("Starting blekeyboard emulator service...")

    transport = HCITransport(dev_id=0)
    broadcaster = BLEBroadcaster(transport)
    server = GattServer(build_database(DEVICE_NAME))
    session = _Session(transport, broadcaster, server)
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

        broadcaster.read_le_buffer_size()
        time.sleep(0.1)

        # Pairing mixes our own address into the confirm value, so it has to
        # be known before a peer can pair.
        broadcaster.read_bd_addr()
        time.sleep(0.1)
        session.drain(transport)

        broadcaster.configure_advertising(interval_ms=400)
        time.sleep(0.1)

        broadcaster.set_advertising_payload(DEVICE_NAME)
        time.sleep(0.1)

        broadcaster.set_state(enable=True)
        print(f"Advertising as '{DEVICE_NAME}'.")
        print("Press Ctrl+C to stop.")

        last_keepalive = time.time()

        while True:
            session.pump(transport.read_packet(timeout_ms=200))

            if time.time() - last_keepalive >= KEEPALIVE_INTERVAL_SECONDS:
                broadcaster.send_keepalive_ping()
                last_keepalive = time.time()

    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"\nFatal error: {e}")
        exit_code = 1
    finally:
        try:
            broadcaster.set_state(enable=False)
        except RuntimeError:
            pass
        transport.release()
        print("Hardware interfaces released.")

    return exit_code


class _Session:
    """Tracks connections and drives the protocol layers above them."""

    def __init__(self, transport, broadcaster, server):
        self._transport = transport
        self._broadcaster = broadcaster
        self._server = server
        self._peers = {}
        self._reassemblers = {}
        self._local_address = b"\x00" * 6

        # Packets that arrived while a controller round trip was in flight.
        # They are replayed once it completes rather than being dropped.
        self._deferred = []

        self._security = SecurityManager(
            self._encrypt_block,
            self._random_bytes,
            self._local_address,
        )

    def pump(self, packet):
        """Processes one packet, then anything deferred behind it."""
        self._dispatch(packet)
        while self._deferred:
            self._dispatch(self._deferred.pop(0))

    def drain(self, transport, timeout_ms=200):
        """Processes whatever is already waiting, used during startup."""
        while True:
            packet = transport.read_packet(timeout_ms=timeout_ms)
            if not packet:
                return
            self.pump(packet)

    def _dispatch(self, packet):
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
        elif isinstance(event, LongTermKeyRequest):
            self._handle_long_term_key_request(event)
        elif isinstance(event, EncryptionChange):
            self._handle_encryption_change(event)
        elif isinstance(event, NumberOfCompletedPackets):
            for _handle, count in event.counts:
                self._transport.credit_acl_packets(count)
        elif isinstance(event, CommandComplete):
            self._handle_command_complete(event)

    def _handle_command_complete(self, event):
        if event.opcode == OPCODE_LE_READ_BUFFER_SIZE:
            capacity = parse_le_buffer_size(event.parameters)
            if capacity is None:
                print("Controller did not report LE buffer capacity; using defaults.")
                return
            payload_length, total_packets = capacity
            self._transport.configure_acl_buffers(payload_length, total_packets)
            print(f"Controller ACL capacity: {self._transport.max_acl_payload} byte "
                  f"payload, {total_packets} buffer(s).")

        elif event.opcode == OPCODE_READ_BD_ADDR and event.status == 0x00:
            self._local_address = bytes(event.parameters[1:7])
            self._security = SecurityManager(
                self._encrypt_block, self._random_bytes, self._local_address)
            print(f"Controller address: {format_address(self._local_address)}.")

    def _handle_connection(self, event):
        if event.status != 0x00:
            print(f"Connection failed with status 0x{event.status:02X}.")
            self._broadcaster.set_state(enable=True)
            return

        self._peers[event.handle] = event.peer_address
        self._reassemblers[event.handle] = L2CAPReassembler()
        self._server.encrypted = False
        self._security.begin_connection(event.peer_address_raw, event.peer_address_type)

        role = "peripheral" if event.role == ROLE_PERIPHERAL else "central"
        print(f"Connected to {event.peer_address} as {role}, handle 0x{event.handle:04X}.")

        # A peripheral cannot start pairing, so it asks the peer to. Some
        # hosts ignore this until they need a protected attribute, in which
        # case pairing begins later instead.
        request = security_request()
        print(f"  SMP -> {_describe(request)} (security request)")
        self._transport.send_acl_payload(event.handle, build_frame(CID_SMP, request))

    def _handle_disconnection(self, event):
        peer = self._peers.pop(event.handle, "unknown peer")
        self._reassemblers.pop(event.handle, None)
        self._server.encrypted = False
        print(f"Disconnected from {peer}, reason 0x{event.reason:02X}.")

        self._broadcaster.set_state(enable=True)
        print(f"Advertising as '{DEVICE_NAME}' again.")

    def _handle_long_term_key_request(self, event):
        key = self._security.long_term_key_for(
            event.encrypted_diversifier, event.random_number)

        if key is None:
            print("  Long term key requested but none is available; declining.")
            self._broadcaster.le_long_term_key_request_negative_reply(event.handle)
            return

        print("  Long term key requested; supplying the session key.")
        self._broadcaster.le_long_term_key_request_reply(event.handle, key)

    def _handle_encryption_change(self, event):
        enabled = event.status == 0x00 and event.enabled != 0x00
        self._security.note_encryption_change(enabled)
        self._server.encrypted = enabled

        if enabled:
            print("  Link is now encrypted.")
        else:
            print(f"  Encryption failed, status 0x{event.status:02X}.")

    def _handle_acl(self, acl):
        reassembler = self._reassemblers.get(acl.handle)
        if reassembler is None:
            print(f"ACL data on unknown handle 0x{acl.handle:04X}; ignoring.")
            return

        for frame in reassembler.feed(acl.packet_boundary, acl.data):
            if frame.cid == CID_ATT:
                self._respond(acl.handle, CID_ATT, "ATT",
                              self._server.handle_pdu(frame.payload), frame.payload)
            elif frame.cid == CID_SMP:
                self._respond(acl.handle, CID_SMP, "SMP",
                              self._security.handle_pdu(frame.payload), frame.payload)
                if self._security.state is State.FAILED:
                    print(f"  Pairing failed, reason "
                          f"0x{self._security.failure_reason or 0:02X}.")
            else:
                print(f"  {frame.channel_name}: {_describe(frame.payload)} (unhandled)")

    def _respond(self, handle, cid, label, response, request):
        print(f"  {label} <- {_describe(request)}")
        if response is None:
            return
        print(f"  {label} -> {_describe(response)}")
        self._transport.send_acl_payload(handle, build_frame(cid, response))

    def _encrypt_block(self, key, block):
        """One AES-128 block through the controller, least significant octet first."""
        self._broadcaster.le_encrypt(key, block)
        parameters = self._await_command(OPCODE_LE_ENCRYPT)
        return parameters[1:17]

    def _random_bytes(self, length):
        """Random octets from the controller, which supplies eight at a time."""
        collected = b""
        while len(collected) < length:
            self._broadcaster.le_rand()
            collected += self._await_command(OPCODE_LE_RAND)[1:9]
        return collected[:length]

    def _await_command(self, opcode, timeout=2.0):
        """
        Waits for one command to complete, holding anything else that arrives.

        Deferred packets are replayed by `pump` afterwards, so a peer's data
        is not lost while a controller round trip is outstanding.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            packet = self._transport.read_packet(timeout_ms=200)
            if not packet:
                continue

            event = parse_event(packet)
            if isinstance(event, CommandComplete) and event.opcode == opcode:
                if event.status != 0x00:
                    raise RuntimeError(
                        f"Command 0x{opcode:04X} failed with status 0x{event.status:02X}.")
                return event.parameters

            self._deferred.append(packet)

        raise RuntimeError(f"Command 0x{opcode:04X} did not complete.")


def _describe(payload: bytes, limit: int = 12) -> str:
    """Renders a PDU as hex, truncated so log lines stay readable."""
    shown = " ".join(f"{b:02X}" for b in payload[:limit])
    if len(payload) > limit:
        shown += " ..."
    return f"{len(payload)}B [{shown}]"


if __name__ == "__main__":
    sys.exit(main())
