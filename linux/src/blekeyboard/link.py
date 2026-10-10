"""
The connection engine: HCI, L2CAP, ATT/GATT and SMP driven from one place.

This is the piece that owns a live connection and the protocol state that
goes with it. `Keyboard` drives it from a background thread; the CLI entry
point drives it directly from its own loop. Either way, `Link` is the same
code, so the two are guaranteed to behave identically.
"""

import secrets
import time

from blekeyboard import crypto
from blekeyboard.hci import (
    ROLE_PERIPHERAL,
    CommandComplete,
    CommandStatus,
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
from blekeyboard.hostprofile import HostGuess, HostSignals, guess_host_os
from blekeyboard.l2cap import CID_ATT, CID_SMP, L2CAPReassembler, build_frame
from blekeyboard.smp import (
    AUTH_REQ_BONDING,
    AUTH_REQ_SECURE_CONNECTIONS,
    BondKeys,
    SecurityManager,
    State,
    security_request,
)

OPCODE_LE_READ_BUFFER_SIZE = 0x2002
OPCODE_LE_ENCRYPT = 0x2017
OPCODE_READ_BD_ADDR = 0x1009


class Link:
    """Tracks one connection and drives the protocol layers above it."""

    def __init__(self, transport, broadcaster, server, input_report, device_name,
                 log=print, bond_store=None):
        self._transport = transport
        self._broadcaster = broadcaster
        self._server = server
        self._input_report = input_report
        self._device_name = device_name
        self._log = log

        # Bonds persisted from earlier runs, so a host that reconnects can
        # resume its encrypted session without pairing again. None disables
        # persistence, which keeps the tests and any embedding that does not
        # want keys on disk to the previous in-memory-only behaviour.
        self._bond_store = bond_store
        self._known_bonds = bond_store.load() if bond_store is not None else []

        self._peers = {}
        self._reassemblers = {}
        self._local_address = b"\x00" * 6
        self.connected_handle = None

        # The current peer's address type, kept for `host_guess` - see
        # hostprofile.py. Not otherwise used; SMP/GATT already read it
        # straight off the events that carry it.
        self._peer_address_type = None

        # Packets that arrived while a controller round trip was in flight.
        # They are replayed once it completes rather than being dropped.
        self._deferred = []

        # The most recently distributed bond, kept in memory only. Unlike
        # `_security`, this survives across `_handle_connection` calls, since
        # its whole purpose is to answer a *later* connection's Long Term Key
        # Request without repeating the SMP pairing exchange.
        self._bond = None

        # The private half of the P-256 key pair for the current Secure
        # Connections exchange, generated in software; see the ECDH note in
        # crypto.py for why this is not delegated to the controller.
        self._ec_private_key = None

        self._security = SecurityManager(
            self._encrypt_block, self._random_bytes, self._local_address,
            generate_keypair=self._generate_local_keypair,
            compute_dhkey=self._compute_dhkey)

    @property
    def is_ready(self):
        """Whether a peer is connected, encrypted, and subscribed to reports."""
        return (
            self.connected_handle is not None
            and self._server.encrypted
            and self._server.is_subscribed(self._input_report)
        )

    @property
    def host_guess(self) -> HostGuess:
        """
        A best-effort guess at the connected peer's OS; see hostprofile.py for
        what this can and cannot actually tell you. Improves as pairing
        progresses - the io_capability/auth_req signals are only available
        once a Pairing Request has arrived, and MTU once negotiated.
        """
        peer_features = self._security.peer_features
        return guess_host_os(HostSignals(
            peer_address_type=self._peer_address_type,
            io_capability=peer_features.io_capability if peer_features else None,
            auth_req=peer_features.auth_req if peer_features else None,
            client_mtu=self._server.client_requested_mtu,
        ))

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
        elif isinstance(event, CommandStatus) and event.status != 0x00:
            # Several LE commands - the P-256/DHKey pair among them - only
            # acknowledge synchronously via Command Status, with the real
            # result arriving later as an LE Meta subevent. A non-zero status
            # here means the controller rejected the command outright and no
            # such subevent is coming; logging it is the difference between
            # seeing why and just watching a later wait time out.
            self._log(f"  Command 0x{event.opcode:04X} rejected, status 0x{event.status:02X}.")

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
                self._encrypt_block, self._random_bytes, self._local_address,
                generate_keypair=self._generate_local_keypair,
                compute_dhkey=self._compute_dhkey)
            self._log(f"Controller address: {format_address(self._local_address)}.")

        elif event.status != 0x00:
            # A controller that does not recognize a command at all often
            # answers with Command Complete rather than Command Status, even
            # for opcodes (like the P-256/DHKey pair) whose successful path
            # normally goes through Command Status instead. Without this,
            # that rejection is as invisible as the Command Status gap was.
            self._log(f"  Command 0x{event.opcode:04X} failed, status 0x{event.status:02X}.")

    def _handle_connection(self, event):
        if event.status != 0x00:
            self._log(f"Connection failed with status 0x{event.status:02X}.")
            self._broadcaster.set_state(enable=True)
            return

        self.connected_handle = event.handle
        self._peers[event.handle] = event.peer_address
        self._reassemblers[event.handle] = L2CAPReassembler()
        self._server.encrypted = False
        self._peer_address_type = event.peer_address_type
        self._security.begin_connection(event.peer_address_raw, event.peer_address_type)

        role = "peripheral" if event.role == ROLE_PERIPHERAL else "central"
        self._log(f"Connected to {event.peer_address} as {role}, handle 0x{event.handle:04X}, "
                  f"connection interval {event.interval_ms:.1f}ms.")

        # A peripheral cannot start pairing, so it asks the peer to. Some
        # hosts ignore this until they need a protected attribute, in which
        # case pairing begins later instead. Requesting bonding and Secure
        # Connections here only states a preference: a responder can never
        # force the peer's own Pairing Request to carry either bit, but a
        # peer capable of SC generally will if it sees this device ask for it.
        request = security_request(AUTH_REQ_BONDING | AUTH_REQ_SECURE_CONNECTIONS)
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
        # A fresh pairing completed this connection takes precedence over any
        # stored bond. The central is starting encryption for the key it just
        # derived; a stored Secure Connections bond resumes with the same zero
        # EDIV/Rand a fresh SC pairing uses, so consulting stored bonds first
        # would hand back a stale key and fail the link's MIC (HCI 0x3D).
        key = self._security.long_term_key_for(
            event.encrypted_diversifier, event.random_number)
        if key is not None:
            self._log("  Long term key requested; supplying the freshly paired key.")
            self._broadcaster.le_long_term_key_request_reply(event.handle, key)
            return

        # No fresh pairing this connection, so a peer here is resuming a bond
        # from an earlier run, naming it by the EDIV/Rand it was given then.
        bond = self._matching_bond(event.encrypted_diversifier, event.random_number)
        if bond is not None:
            self._log("  Long term key requested; resuming an existing bond.")
            self._broadcaster.le_long_term_key_request_reply(event.handle, bond.ltk)
            return

        self._log("  Long term key requested but none is available; declining.")
        self._broadcaster.le_long_term_key_request_negative_reply(event.handle)

    def _matching_bond(self, encrypted_diversifier, random_number):
        """The stored bond a resume request names, or None if none matches."""
        if self._bond is not None and self._bond.matches(
                encrypted_diversifier, random_number):
            return self._bond
        for bond in self._known_bonds:
            if bond.matches(encrypted_diversifier, random_number):
                return bond
        return None

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
        guess = self.host_guess
        self._log(f"  Host guess: {guess.os.name} (confidence: {guess.confidence}).")
        if completed_fresh_pairing:
            self._distribute_bond_keys()

    def _distribute_bond_keys(self):
        """
        Records a Long Term Key for future reconnection.

        Sent immediately after Phase 2 pairing encrypts the link, per the
        responder key distribution this implementation declares in its
        Pairing Response. Without this, several hosts - Android's HID input
        framework and iOS both - never treat the peripheral as genuinely
        bonded, regardless of whether the current session is encrypted.

        Secure Connections derives a durable LTK as part of the key exchange
        itself, so there is nothing further to distribute: the Pairing
        Response already declared no responder key distribution, and this
        just remembers that same key for a later reconnection. Legacy has no
        such key yet, so it generates one and sends the two PDUs that hand it
        to the peer.
        """
        if self._security.use_sc:
            self._bond = BondKeys(ltk=self._security.short_term_key, ediv=0, rand=bytes(8))
            self._remember_bond(self._bond)
            return

        self._bond = self._security.create_bond_keys()
        encryption_information, master_identification = self._bond.encode_pdus()

        for pdu in (encryption_information, master_identification):
            self._log(f"  SMP -> {_describe(pdu)} (key distribution)")
            self._transport.send_acl_payload(
                self.connected_handle, build_frame(CID_SMP, pdu))

        self._remember_bond(self._bond)

    def _remember_bond(self, bond):
        """
        Keeps a freshly formed bond for this run and, if persistence is on,
        writes it to disk so a later run can resume it too.

        A failure to persist is logged but never fatal: the bond still works
        for the current session, and losing it only costs a re-pairing on a
        future run - not a reason to tear down a connection that is otherwise
        fine.
        """
        self._known_bonds = [
            b for b in self._known_bonds
            if not (b.ediv == bond.ediv and b.rand == bond.rand)
        ]
        self._known_bonds.append(bond)

        if self._bond_store is None:
            return
        try:
            self._bond_store.add(bond)
        except OSError as error:
            self._log(f"  Could not persist bond: {error}.")

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
                for pdu in self._security.drain_queued_pdus():
                    self._log(f"  SMP -> {_describe(pdu)}")
                    self._transport.send_acl_payload(acl.handle, build_frame(CID_SMP, pdu))
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
        """
        Cryptographically strong random octets for pairing nonces and keys.

        Sourced from the OS CSPRNG rather than the controller's LE Rand
        command. LE Rand is documented to defer until in-flight radio
        operations finish, and in practice, calling it right after
        LE Generate DHKey during an active Secure Connections pairing never
        completes at all - the link's own connection events keep the radio
        busy indefinitely. secrets.token_bytes has no such coupling to radio
        state and needs no HCI round trip mid-handshake, while remaining a
        standard-library CSPRNG, so the package stays dependency-free and the
        pairing path loses a fragile timing dependency. A nonce or key only
        needs to be unpredictable, which this fully satisfies; it never has
        to originate in the controller.
        """
        return secrets.token_bytes(length)

    def _generate_local_keypair(self) -> bytes:
        """
        A fresh P-256 public key for this connection's Secure Connections
        exchange, generated in software.

        The private half is retained for the later DHKey computation. See the
        ECDH note in crypto.py for why this is not delegated to the
        controller's LE Read Local P-256 Public Key command.
        """
        self._ec_private_key, public_key = crypto.generate_p256_keypair()
        return public_key

    def _compute_dhkey(self, remote_public_key: bytes) -> bytes:
        """
        The ECDH shared secret between this connection's key pair and the
        peer's public key, computed in software rather than through the
        controller's LE Generate DHKey command.
        """
        return crypto.p256_compute_dhkey(self._ec_private_key, remote_public_key)

    def _await_command(self, opcode, timeout=2.0):
        """
        Waits for one command to complete, holding anything else that arrives.

        Deferred packets are replayed by `pump` afterwards, so a peer's data
        is not lost while a controller round trip is outstanding.
        """
        deadline = time.time() + timeout
        seen = []
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

            seen.append(packet)
            self._deferred.append(packet)

        self._log_await_timeout(f"Command 0x{opcode:04X}", seen)
        raise RuntimeError(f"Command 0x{opcode:04X} did not complete.")

    def _log_await_timeout(self, waiting_for, seen):
        """
        Reports what actually arrived while a controller round trip timed out.

        These wait loops otherwise discard every packet that is not the one
        they want, so a timeout gives no hint whether the controller stayed
        silent or answered with something unexpected. On the rare timeout
        path that difference is exactly what is needed to tell a stalled
        controller from a misrouted reply, so it is worth surfacing.
        """
        if not seen:
            self._log(f"  {waiting_for} timed out; controller sent nothing back.")
            return
        self._log(f"  {waiting_for} timed out after {len(seen)} other packet(s):")
        for packet in seen:
            event = parse_event(packet)
            label = type(event).__name__ if event is not None else "unparsed"
            self._log(f"    {label}: {_describe(bytes(packet))}")


def _describe(payload: bytes, limit: int = 12) -> str:
    """Renders a PDU as hex, truncated so log lines stay readable."""
    shown = " ".join(f"{b:02X}" for b in payload[:limit])
    if len(payload) > limit:
        shown += " ..."
    return f"{len(payload)}B [{shown}]"
