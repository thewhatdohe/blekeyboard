"""
The connection engine: HCI, L2CAP, ATT/GATT and SMP driven from one place.

This is the piece that owns a live connection and the protocol state that
goes with it. `Keyboard` drives it from a background thread; the CLI entry
point drives it directly from its own loop. Either way, `Link` is the same
code, so the two are guaranteed to behave identically.
"""

import time

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
from blekeyboard.hid_report_map import build_input_report
from blekeyboard.l2cap import CID_ATT, CID_SMP, L2CAPReassembler, build_frame
from blekeyboard.smp import SecurityManager, State, security_request

OPCODE_LE_READ_BUFFER_SIZE = 0x2002
OPCODE_LE_ENCRYPT = 0x2017
OPCODE_LE_RAND = 0x2018
OPCODE_READ_BD_ADDR = 0x1009


class Link:
    """Tracks one connection and drives the protocol layers above it."""

    def __init__(self, transport, broadcaster, server, input_report, device_name, log=print):
        self._transport = transport
        self._broadcaster = broadcaster
        self._server = server
        self._input_report = input_report
        self._device_name = device_name
        self._log = log

        self._peers = {}
        self._reassemblers = {}
        self._local_address = b"\x00" * 6
        self.connected_handle = None

        # Packets that arrived while a controller round trip was in flight.
        # They are replayed once it completes rather than being dropped.
        self._deferred = []

        # The most recently distributed bond, kept in memory only. Unlike
        # `_security`, this survives across `_handle_connection` calls, since
        # its whole purpose is to answer a *later* connection's Long Term Key
        # Request without repeating the SMP pairing exchange.
        self._bond = None

        self._security = SecurityManager(
            self._encrypt_block, self._random_bytes, self._local_address)

    @property
    def is_ready(self):
        """Whether a peer is connected, encrypted, and subscribed to reports."""
        return (
            self.connected_handle is not None
            and self._server.encrypted
            and self._server.is_subscribed(self._input_report)
        )

    def send_key_report(self, modifier: int, keycodes=()) -> bool:
        """
        Sends one input report, if a peer is ready to receive it.

        Returns whether it was actually sent, so a caller can tell an
        unready link from a genuine transport failure.
        """
        if not self.is_ready:
            return False

        report = build_input_report(modifier, keycodes)
        self._input_report.value = report
        pdu = self._server.build_notification(self._input_report, report)
        self._log(f"  ATT -> {_describe(pdu)} (input report notification)")
        self._transport.send_acl_payload(self.connected_handle, build_frame(CID_ATT, pdu))
        return True

    def pump(self, packet):
        """Processes one packet, then anything deferred behind it."""
        self._dispatch(packet)
        while self._deferred:
            self._dispatch(self._deferred.pop(0))

    def drain(self, timeout_ms=200):
        """Processes whatever is already waiting, used during startup."""
        while True:
            packet = self._transport.read_packet(timeout_ms=timeout_ms)
            if not packet:
                return
            self.pump(packet)

    def initialize(self):
        """Resets the controller and configures it to accept a connection."""
        self._broadcaster.reset_controller()
        time.sleep(0.1)

        # The reset default masks off LE Meta events, so connection events
        # would never reach us without this.
        self._broadcaster.set_event_mask()
        self._broadcaster.set_le_event_mask()
        time.sleep(0.1)

        self._broadcaster.read_le_buffer_size()
        time.sleep(0.1)

        # Pairing mixes our own address into the confirm value, so it has to
        # be known before a peer can pair.
        self._broadcaster.read_bd_addr()
        time.sleep(0.1)
        self.drain()

        self._broadcaster.configure_advertising(interval_ms=400)
        time.sleep(0.1)

        self._broadcaster.set_advertising_payload(
            self._device_name, service_uuids=[0x1812])
        time.sleep(0.1)

        self._broadcaster.set_state(enable=True)
        self._log(f"Advertising as '{self._device_name}'.")

    def send_keepalive(self):
        """Pings the controller so it does not consider the process stalled."""
        self._broadcaster.send_keepalive_ping()

    def shutdown(self):
        try:
            self._broadcaster.set_state(enable=False)
        except RuntimeError:
            pass

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
                self._log("Controller did not report LE buffer capacity; using defaults.")
                return
            payload_length, total_packets = capacity
            self._transport.configure_acl_buffers(payload_length, total_packets)
            self._log(f"Controller ACL capacity: {self._transport.max_acl_payload} byte "
                      f"payload, {total_packets} buffer(s).")

        elif event.opcode == OPCODE_READ_BD_ADDR and event.status == 0x00:
            self._local_address = bytes(event.parameters[1:7])
            self._security = SecurityManager(
                self._encrypt_block, self._random_bytes, self._local_address)
            self._log(f"Controller address: {format_address(self._local_address)}.")

    def _handle_connection(self, event):
        if event.status != 0x00:
            self._log(f"Connection failed with status 0x{event.status:02X}.")
            self._broadcaster.set_state(enable=True)
            return

        self.connected_handle = event.handle
        self._peers[event.handle] = event.peer_address
        self._reassemblers[event.handle] = L2CAPReassembler()
        self._server.encrypted = False
        self._security.begin_connection(event.peer_address_raw, event.peer_address_type)

        role = "peripheral" if event.role == ROLE_PERIPHERAL else "central"
        self._log(f"Connected to {event.peer_address} as {role}, handle 0x{event.handle:04X}, "
                  f"connection interval {event.interval_ms:.1f}ms.")

        # A peripheral cannot start pairing, so it asks the peer to. Some
        # hosts ignore this until they need a protected attribute, in which
        # case pairing begins later instead.
        request = security_request()
        self._log(f"  SMP -> {_describe(request)} (security request)")
        self._transport.send_acl_payload(event.handle, build_frame(CID_SMP, request))

    def _handle_disconnection(self, event):
        peer = self._peers.pop(event.handle, "unknown peer")
        self._reassemblers.pop(event.handle, None)
        self._server.encrypted = False
        if self.connected_handle == event.handle:
            self.connected_handle = None
        self._log(f"Disconnected from {peer}, reason 0x{event.reason:02X}.")

        self._broadcaster.set_state(enable=True)
        self._log(f"Advertising as '{self._device_name}' again.")

    def _handle_long_term_key_request(self, event):
        # A peer resuming a previous bond skips SMP pairing entirely and asks
        # for this key directly, naming it by the EDIV/Rand it was given when
        # the bond was formed. Checked first, since `_security` was reset for
        # this connection and would have no session key to offer such a peer.
        if self._bond is not None and self._bond.matches(
                event.encrypted_diversifier, event.random_number):
            self._log("  Long term key requested; resuming the existing bond.")
            self._broadcaster.le_long_term_key_request_reply(event.handle, self._bond.ltk)
            return

        key = self._security.long_term_key_for(
            event.encrypted_diversifier, event.random_number)

        if key is None:
            self._log("  Long term key requested but none is available; declining.")
            self._broadcaster.le_long_term_key_request_negative_reply(event.handle)
            return

        self._log("  Long term key requested; supplying the session key.")
        self._broadcaster.le_long_term_key_request_reply(event.handle, key)

    def _handle_encryption_change(self, event):
        enabled = event.status == 0x00 and event.enabled != 0x00
        # A fresh SMP pairing happened this connection if and only if a
        # session key was derived; a resumed bond leaves this None, and
        # there is nothing new to distribute in that case.
        completed_fresh_pairing = self._security.short_term_key is not None
        self._security.note_encryption_change(enabled)
        self._server.encrypted = enabled

        if not enabled:
            self._log(f"  Encryption failed, status 0x{event.status:02X}.")
            return

        self._log("  Link is now encrypted.")
        if completed_fresh_pairing:
            self._distribute_bond_keys()

    def _distribute_bond_keys(self):
        """
        Hands the peer a Long Term Key for future reconnection.

        Sent immediately after Phase 2 pairing encrypts the link, per the
        responder key distribution this implementation declares in its
        Pairing Response. Without this, several hosts - Android's HID input
        framework among them - never treat the peripheral as genuinely
        bonded, regardless of whether the current session is encrypted.
        """
        self._bond = self._security.create_bond_keys()
        encryption_information, master_identification = self._bond.encode_pdus()

        for pdu in (encryption_information, master_identification):
            self._log(f"  SMP -> {_describe(pdu)} (key distribution)")
            self._transport.send_acl_payload(
                self.connected_handle, build_frame(CID_SMP, pdu))

    def _handle_acl(self, acl):
        reassembler = self._reassemblers.get(acl.handle)
        if reassembler is None:
            self._log(f"ACL data on unknown handle 0x{acl.handle:04X}; ignoring.")
            return

        for frame in reassembler.feed(acl.packet_boundary, acl.data):
            if frame.cid == CID_ATT:
                self._respond(acl.handle, CID_ATT, "ATT",
                              self._server.handle_pdu(frame.payload), frame.payload)
            elif frame.cid == CID_SMP:
                self._respond(acl.handle, CID_SMP, "SMP",
                              self._security.handle_pdu(frame.payload), frame.payload)
                if self._security.state is State.FAILED:
                    self._log(f"  Pairing failed, reason "
                              f"0x{self._security.failure_reason or 0:02X}.")
            else:
                self._log(f"  {frame.channel_name}: {_describe(frame.payload)} (unhandled)")

    def _respond(self, handle, cid, label, response, request):
        self._log(f"  {label} <- {_describe(request)}")
        if response is None:
            return
        self._log(f"  {label} -> {_describe(response)}")
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
