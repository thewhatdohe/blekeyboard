from blekeyboard import att, crypto, smp
from blekeyboard.bonds import BondStore
from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.gatt import GattServer
from blekeyboard.hci import ACL_PB_FIRST, build_acl, parse_acl
from blekeyboard.hostprofile import HostOS
from blekeyboard.l2cap import CID_SMP, L2CAPReassembler, build_frame
from blekeyboard.link import Link
from blekeyboard.profile import build_database

OPCODE_LE_ENCRYPT = 0x2017


def fake_hardware_encrypt(key, block):
    """Stands in for the controller's LE Encrypt in these wiring tests."""
    return bytes(((b * 7) + key[0] + 13) & 0xFF for b in block)


class RecordingTransport:
    """
    A transport stub that records outbound ACL payloads.

    Answers LE Encrypt with a synthetic Command Complete event, since the
    Secure Connections crypto (f4/f5/f6, all built on AES-CMAC) drives the
    controller's AES engine and would otherwise hang waiting for a reply
    that never comes. The ECDH commands are deliberately not answered here:
    the key agreement is now done in software, so a well-behaved run never
    sends them.
    """

    def __init__(self):
        self.sent = []
        self.control_packets = []
        self.max_acl_payload = 27
        self.total_acl_credits = 0
        self.available_acl_credits = 0
        self._queued_events = []

    def send_control_packet(self, packet):
        self.control_packets.append(packet)
        # Packet layout is [opcode_lo, opcode_hi, length, *data], per
        # BLEBroadcaster._build_hci_packet - no leading H4 byte here, since
        # that framing is added inside the real transport, not by the caller.
        opcode = packet[0] | (packet[1] << 8)
        if opcode == OPCODE_LE_ENCRYPT:
            key = bytes(packet[3:19])
            block = bytes(packet[19:35])
            result = fake_hardware_encrypt(key, block)
            params = [0x01] + [opcode & 0xFF, opcode >> 8] + [0x00] + list(result)
            self._queued_events.append([0x04, 0x0E, len(params)] + params)

    def configure_acl_buffers(self, payload_length, total_packets):
        pass

    def credit_acl_packets(self, count):
        pass

    def send_acl_payload(self, handle, payload):
        self.sent.append((handle, payload))
        return 1

    def read_packet(self, timeout_ms=200):
        if self._queued_events:
            return self._queued_events.pop(0)
        return []


def make_link(bond_store=None):
    transport = RecordingTransport()
    broadcaster = BLEBroadcaster(transport)
    database, input_report = build_database("BLE-Ducky")
    server = GattServer(database)
    link = Link(transport, broadcaster, server, input_report, "BLE-Ducky",
                log=lambda _m: None, bond_store=bond_store)
    return link, server, input_report, transport


def connection_complete_packet(handle=0x0010, address_type=0x00):
    """A raw LE Connection Complete event, peripheral role, public address by default."""
    return (
        [0x04, 0x3E, 0x13, 0x01, 0x00]
        + list(handle.to_bytes(2, "little"))
        + [0x01, address_type] + [0xAA] * 6
        + [0x18, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00]
    )


def disconnection_complete_packet(handle=0x0010, reason=0x13):
    return [0x04, 0x05, 0x04, 0x00] + list(handle.to_bytes(2, "little")) + [reason]


def encryption_change_packet(handle=0x0010, enabled=True, status=0x00):
    return [0x04, 0x08, 0x04, status] + list(handle.to_bytes(2, "little")) + [1 if enabled else 0]


def command_status_packet(opcode, status=0x01):
    return [0x04, 0x0F, 0x04, status, 0x01, opcode & 0xFF, opcode >> 8]


def command_complete_packet(opcode, status=0x01):
    return [0x04, 0x0E, 0x04, 0x01, opcode & 0xFF, opcode >> 8, status]


def long_term_key_request_packet(handle=0x0010, ediv=0, rand=None):
    rand = rand or bytes(8)
    return (
        [0x04, 0x3E, 0x0D, 0x05] + list(handle.to_bytes(2, "little"))
        + list(rand) + list(ediv.to_bytes(2, "little"))
    )


def subscribe(server, input_report):
    """Writes the notification-enable bit to the input report's CCCD."""
    pdu = bytes([att.WRITE_REQUEST]) + (input_report.handle + 1).to_bytes(2, "little") \
        + b"\x01\x00"
    server.handle_pdu(pdu)


def smp_acl_packet(handle, payload):
    return build_acl(handle, ACL_PB_FIRST, build_frame(CID_SMP, payload))


def sc_pairing_request_pdu(auth_req=smp.AUTH_REQ_SECURE_CONNECTIONS | smp.AUTH_REQ_BONDING):
    return smp.PairingFeatures(
        io_capability=smp.IO_CAPABILITY_NO_INPUT_NO_OUTPUT,
        oob_data_flag=0x00,
        auth_req=auth_req,
        max_key_size=16,
        initiator_key_distribution=0x00,
        responder_key_distribution=0x00,
    ).encode(smp.PAIRING_REQUEST)


class TestReadiness:
    def test_not_ready_with_no_connection(self):
        link, *_ = make_link()
        assert not link.is_ready

    def test_not_ready_when_connected_but_unencrypted(self):
        link, *_ = make_link()
        link.pump(connection_complete_packet())
        assert link.connected_handle == 0x0010
        assert not link.is_ready

    def test_not_ready_when_encrypted_but_unsubscribed(self):
        link, server, _input_report, _transport = make_link()
        link.pump(connection_complete_packet())
        server.encrypted = True
        assert not link.is_ready

    def test_ready_once_connected_encrypted_and_subscribed(self):
        link, server, input_report, _transport = make_link()
        link.pump(connection_complete_packet())
        server.encrypted = True
        subscribe(server, input_report)
        assert link.is_ready

    def test_disconnection_clears_readiness(self):
        link, server, input_report, _transport = make_link()
        link.pump(connection_complete_packet())
        server.encrypted = True
        subscribe(server, input_report)
        assert link.is_ready

        link.pump(disconnection_complete_packet())
        assert link.connected_handle is None
        assert not link.is_ready
        assert not server.encrypted

    def test_a_failed_connection_attempt_leaves_nothing_connected(self):
        link, *_ = make_link()
        failed = [0x04, 0x3E, 0x13, 0x01, 0x0E] + [0x00] * 17
        link.pump(failed)
        assert link.connected_handle is None


class TestSendKeyReport:
    def test_refused_when_not_ready(self):
        link, *_ = make_link()
        assert link.send_key_report(0, [0x04]) is False

    def test_nothing_is_sent_when_not_ready(self):
        link, *_, transport = make_link()
        link.send_key_report(0, [0x04])
        assert transport.sent == []

    def test_sent_report_reaches_the_connected_handle(self):
        link, server, input_report, transport = make_link()
        link.pump(connection_complete_packet(handle=0x0022))
        server.encrypted = True
        subscribe(server, input_report)

        assert link.send_key_report(0x02, [0x04]) is True
        handle, _payload = transport.sent[-1]
        assert handle == 0x0022

    def test_sent_pdu_is_a_notification_carrying_the_report(self):
        link, server, input_report, transport = make_link()
        link.pump(connection_complete_packet())
        server.encrypted = True
        subscribe(server, input_report)

        link.send_key_report(0x02, [0x04])
        _handle, frame = transport.sent[-1]

        # The frame is L2CAP: length, CID, then the ATT PDU.
        pdu = frame[4:]
        assert pdu[0] == att.HANDLE_VALUE_NOTIFICATION
        assert int.from_bytes(pdu[1:3], "little") == input_report.handle

        # The report has no report ID prefix: modifier is byte 0, the key
        # array starts at byte 2.
        report = pdu[3:]
        assert report[0] == 0x02          # modifier
        assert report[2] == 0x04          # first keycode

    def test_attribute_value_is_updated_for_a_subsequent_read(self):
        link, server, input_report, _transport = make_link()
        link.pump(connection_complete_packet())
        server.encrypted = True
        subscribe(server, input_report)

        link.send_key_report(0x00, [0x05])
        assert input_report.value[2] == 0x05


class TestBondKeyDistribution:
    def _connected_with_fresh_pairing(self):
        """A connection where SMP pairing genuinely completed this session."""
        link, server, input_report, transport = make_link()
        link.pump(connection_complete_packet())
        # Standing in for a completed Phase 2 exchange without re-driving the
        # full Confirm/Random handshake, which test_smp.py already covers.
        link._security._short_term_key = bytes(range(16))
        return link, server, input_report, transport

    def test_encryption_after_fresh_pairing_distributes_a_bond(self):
        link, *_ = self._connected_with_fresh_pairing()
        link.pump(encryption_change_packet(enabled=True))
        assert link._bond is not None

    def test_distributed_bond_has_the_expected_shape(self):
        link, *_ = self._connected_with_fresh_pairing()
        link.pump(encryption_change_packet(enabled=True))
        assert len(link._bond.ltk) == 16
        assert len(link._bond.rand) == 8

    def test_key_distribution_sends_encryption_information_then_master_identification(self):
        link, _server, _input_report, transport = self._connected_with_fresh_pairing()
        link.pump(encryption_change_packet(enabled=True))

        smp_frames = [p for h, p in transport.sent if h == 0x0010]
        # L2CAP header is 4 bytes; the SMP opcode follows immediately.
        opcodes = [frame[4] for frame in smp_frames[-2:]]
        assert opcodes == [smp.ENCRYPTION_INFORMATION, smp.MASTER_IDENTIFICATION]

    def test_distributed_ltk_matches_what_was_sent_on_the_wire(self):
        link, *_ = self._connected_with_fresh_pairing()
        link.pump(encryption_change_packet(enabled=True))

        transport = link._transport
        smp_frames = [p for h, p in transport.sent if h == 0x0010]
        encryption_information = smp_frames[-2]
        assert encryption_information[5:] == link._bond.ltk

    def test_failed_encryption_distributes_no_bond(self):
        link, *_ = self._connected_with_fresh_pairing()
        link.pump(encryption_change_packet(enabled=False, status=0x05))
        assert link._bond is None

    def test_encryption_without_a_fresh_pairing_distributes_nothing(self):
        # A resumed bond re-encrypts without SMP running again this
        # connection, so there is nothing new to hand out.
        link, *_ = make_link()
        link.pump(connection_complete_packet())
        link.pump(encryption_change_packet(enabled=True))
        assert link._bond is None


class TestResumedBond:
    def _linked_bond(self):
        link, *_ = make_link()
        return link, smp.BondKeys(ltk=bytes(range(16)), ediv=0x1234, rand=bytes(range(8)))

    def test_matching_request_is_answered_with_the_stored_ltk(self):
        link, bond = self._linked_bond()
        link._bond = bond
        link.pump(connection_complete_packet())
        transport = link._transport

        link.pump(long_term_key_request_packet(ediv=bond.ediv, rand=bond.rand))

        # OCF 0x001A under the LE group (opcode 0x201A) is
        # LE Long Term Key Request Reply: opcode, length, handle, then the key.
        reply = transport.control_packets[-1]
        assert (reply[0], reply[1]) == (0x1A, 0x20)
        assert bytes(reply[5:21]) == bond.ltk

        # And no fresh SMP pairing was needed to answer it.
        assert link._security.short_term_key is None

    def test_non_matching_request_falls_back_to_a_negative_reply(self):
        link, bond = self._linked_bond()
        link._bond = bond
        link.pump(connection_complete_packet())
        transport = link._transport

        link.pump(long_term_key_request_packet(ediv=bond.ediv, rand=bytes(range(1, 9))))

        # OCF 0x001B, opcode 0x201B: LE Long Term Key Request Negative Reply.
        reply = transport.control_packets[-1]
        assert (reply[0], reply[1]) == (0x1B, 0x20)

    def test_bond_survives_a_new_connection(self):
        link, bond = self._linked_bond()
        link._bond = bond
        link.pump(connection_complete_packet())
        link.pump(disconnection_complete_packet())
        link.pump(connection_complete_packet())

        assert link._bond is bond


class TestBondPersistence:
    def _sc_paired_link(self, bond_store):
        """A link whose current connection just completed fresh SC pairing."""
        link, _server, _input_report, transport = make_link(bond_store=bond_store)
        link.pump(connection_complete_packet())
        link._security._use_sc = True
        link._security._short_term_key = bytes(range(16))
        return link, transport

    def test_a_formed_sc_bond_is_written_to_the_store(self, tmp_path):
        store = BondStore(tmp_path / "bonds.json")
        link, _ = self._sc_paired_link(store)
        link.pump(encryption_change_packet(enabled=True))

        persisted = store.load()
        assert len(persisted) == 1
        assert persisted[0].ltk == link._bond.ltk

    def test_a_persisted_bond_is_resumed_by_a_fresh_link(self, tmp_path):
        # The whole point: a new process (a new Link) reconnecting must be
        # able to answer the resume request from the key on disk alone.
        store = BondStore(tmp_path / "bonds.json")
        first, _ = self._sc_paired_link(store)
        first.pump(encryption_change_packet(enabled=True))
        saved_ltk = first._bond.ltk

        fresh, _server, _input_report, transport = make_link(bond_store=store)
        fresh.pump(connection_complete_packet())
        # An SC resume names its bond with a zero EDIV/Rand, and reconnects
        # from a rotating address, so nothing but that key identifies it.
        fresh.pump(long_term_key_request_packet(ediv=0, rand=bytes(8)))

        reply = transport.control_packets[-1]
        assert (reply[0], reply[1]) == (0x1A, 0x20)  # LE LTK Request Reply
        assert bytes(reply[5:21]) == saved_ltk

    def test_a_fresh_pairing_key_beats_a_stale_stored_bond(self, tmp_path):
        # A stored SC bond and a fresh SC pairing both present a zero
        # EDIV/Rand, so the freshly derived key must win. Handing back the
        # stale stored key instead fails the link's MIC (HCI 0x3D) - the exact
        # bug that let a leftover bond shadow every re-pairing.
        store = BondStore(tmp_path / "bonds.json")
        store.add(smp.BondKeys(ltk=bytes([0x11]) * 16, ediv=0, rand=bytes(8)))

        link, _server, _input_report, transport = make_link(bond_store=store)
        link.pump(connection_complete_packet())
        # Stand in for a completed fresh SC pairing this connection.
        link._security._use_sc = True
        link._security._short_term_key = bytes([0x99]) * 16

        link.pump(long_term_key_request_packet(ediv=0, rand=bytes(8)))

        reply = transport.control_packets[-1]
        assert (reply[0], reply[1]) == (0x1A, 0x20)  # LE LTK Request Reply
        assert bytes(reply[5:21]) == bytes([0x99]) * 16  # fresh key, not 0x11

    def test_without_a_store_nothing_is_persisted(self, tmp_path):
        # The default for a bare Link is in-memory only; a bond forms and
        # works this session but leaves nothing on disk.
        link, _ = self._sc_paired_link(bond_store=None)
        link.pump(encryption_change_packet(enabled=True))
        assert link._bond is not None
        assert not (tmp_path / "bonds.json").exists()

    def test_a_persist_failure_does_not_break_the_session(self, tmp_path):
        # If the key cannot be written, the bond must still work for now; a
        # lost bond only costs a future re-pairing, not this connection.
        class FailingStore:
            def load(self):
                return []

            def add(self, bond):
                raise OSError("read-only file system")

        link, _ = self._sc_paired_link(FailingStore())
        link.pump(encryption_change_packet(enabled=True))
        assert link._bond is not None


class TestCommandStatusLogging:
    def _linked_with_logs(self):
        transport = RecordingTransport()
        broadcaster = BLEBroadcaster(transport)
        database, input_report = build_database("BLE-Ducky")
        server = GattServer(database)
        logs = []
        link = Link(transport, broadcaster, server, input_report, "BLE-Ducky", log=logs.append)
        return link, logs

    def test_a_rejected_command_is_logged(self):
        # A non-zero Command Status is the controller refusing a command
        # outright - for the P-256/DHKey pair, the only sign anything went
        # wrong, since no LE Meta subevent follows to time out on instead.
        link, logs = self._linked_with_logs()
        link.pump(command_status_packet(0x2025, status=0x01))
        assert any("0x2025" in line and "0x01" in line for line in logs)

    def test_a_successful_command_status_is_not_logged(self):
        link, logs = self._linked_with_logs()
        link.pump(command_status_packet(0x2025, status=0x00))
        assert logs == []

    def test_an_unrecognized_command_complete_failure_is_logged(self):
        # Some controllers answer a command they don't recognize at all via
        # Command Complete rather than Command Status, even for opcodes
        # whose successful path normally goes through Command Status instead.
        link, logs = self._linked_with_logs()
        link.pump(command_complete_packet(0x2025, status=0x01))
        assert any("0x2025" in line and "0x01" in line for line in logs)

    def test_a_successful_command_complete_for_an_unhandled_opcode_is_not_logged(self):
        link, logs = self._linked_with_logs()
        link.pump(command_complete_packet(0x9999, status=0x00))
        assert logs == []

    def test_await_timeout_reports_that_the_controller_was_silent(self):
        # A transport that never answers a command reproduces the "controller
        # sent nothing back" case; the log must say so rather than leaving a
        # bare timeout with no explanation.
        link, logs = self._linked_with_logs()
        try:
            link._await_command(0x2018, timeout=0.05)
        except RuntimeError:
            pass
        assert any("timed out" in line and "nothing" in line for line in logs)


class TestSecureConnectionsBondDistribution:
    def _connected_with_fresh_sc_pairing(self):
        link, server, input_report, transport = make_link()
        link.pump(connection_complete_packet())
        link._security._use_sc = True
        link._security._short_term_key = bytes(range(16))
        return link, server, input_report, transport

    def test_bond_is_the_sc_derived_key_directly(self):
        link, *_ = self._connected_with_fresh_sc_pairing()
        link.pump(encryption_change_packet(enabled=True))
        assert link._bond.ltk == link._security.short_term_key
        assert link._bond.ediv == 0

    def test_no_enc_key_or_master_identification_pdus_are_sent(self):
        # SC's key exchange already produced the durable LTK; there is no
        # separate responder key distribution phase to run for it.
        link, _server, _input_report, transport = self._connected_with_fresh_sc_pairing()
        link.pump(encryption_change_packet(enabled=True))

        smp_frames = [p for h, p in transport.sent if h == 0x0010]
        opcodes = [frame[4] for frame in smp_frames]
        assert smp.ENCRYPTION_INFORMATION not in opcodes
        assert smp.MASTER_IDENTIFICATION not in opcodes


class TestSecureConnectionsKeyAgreement:
    def test_generate_local_keypair_produces_a_valid_public_point(self):
        # The key agreement is done in software now; the public key must be a
        # genuine 64-octet P-256 point, not a controller round trip.
        link, *_ = make_link()
        public = link._generate_local_keypair()

        assert len(public) == 64
        x = int.from_bytes(public[:32], "little")
        y = int.from_bytes(public[32:], "little")
        assert crypto._p256_on_curve(x, y)

    def test_generate_local_keypair_needs_no_controller_command(self):
        link, _server, _input_report, transport = make_link()
        transport.control_packets.clear()
        link._generate_local_keypair()
        assert transport.control_packets == []

    def test_compute_dhkey_matches_the_shared_secret_from_the_peers_side(self):
        # Both sides of a real exchange must arrive at the same secret: our
        # private key against the peer's public key, and vice versa.
        link, *_ = make_link()
        our_public = link._generate_local_keypair()

        peer_private, peer_public = crypto.generate_p256_keypair()
        ours = link._compute_dhkey(peer_public)
        theirs = crypto.p256_compute_dhkey(peer_private, our_public)
        assert ours == theirs


class TestHostGuess:
    def test_no_guess_information_before_any_connection(self):
        link, *_ = make_link()
        assert link.host_guess.confidence == "none"

    def test_reflects_address_type_right_after_connecting(self):
        link, *_ = make_link()
        link.pump(connection_complete_packet())
        # connection_complete_packet() uses public address type 0x00, so
        # only the "desktop-typical address" signal is available yet.
        guess = link.host_guess
        assert guess.os is HostOS.UNKNOWN
        assert guess.confidence == "low"

    def test_improves_once_a_pairing_request_arrives(self):
        # Address type alone (random, i.e. phone-like) leaves auth_req still
        # unknown; a Pairing Request with the SC+CT2 pattern this project has
        # captured from iOS should sharpen the guess to IOS/medium.
        link, _server, _input_report, transport = make_link()
        link.pump(connection_complete_packet(address_type=0x01))
        before = link.host_guess
        assert before.os is HostOS.ANDROID  # default guess with no auth_req yet
        assert before.confidence == "low"

        link.pump(smp_acl_packet(link.connected_handle, sc_pairing_request_pdu(
            auth_req=smp.AUTH_REQ_SECURE_CONNECTIONS | smp.AUTH_REQ_BONDING | 0x20)))
        after = link.host_guess

        assert after.os is HostOS.IOS
        assert after.confidence == "medium"
        assert after.reasons != before.reasons


class TestSecurityRequestAskedBits:
    def test_security_request_asks_for_bonding_and_secure_connections(self):
        link, _server, _input_report, transport = make_link()
        link.pump(connection_complete_packet())

        smp_frames = [p for h, p in transport.sent if h == 0x0010]
        security_request = smp_frames[0]
        assert security_request[4] == smp.SECURITY_REQUEST
        assert security_request[5] == smp.AUTH_REQ_BONDING | smp.AUTH_REQ_SECURE_CONNECTIONS


class TestSecureConnectionsPairingOverTheWire:
    """
    Drives a full LE Secure Connections Just Works pairing through
    `link.pump()`, playing the initiator's side with the same real crypto
    primitives the rest of the suite cross-checks against independent
    references. The initiator here is a genuine software P-256 party, so the
    peer public key is a real curve point and the DHKey both sides derive is
    a real shared secret - the wiring under test is the software key
    agreement plus the queued-PDU draining that lets one inbound Public Key
    PDU produce both a Public Key and a Pairing Confirm on the wire.
    """

    def _connected(self):
        link, server, input_report, transport = make_link()
        link.pump(connection_complete_packet())
        return link, server, input_report, transport

    def _own_public_key_from_wire(self, transport, handle):
        """The 64-octet public key the link put in its outbound Public Key PDU."""
        for _h, payload in transport.sent:
            pdu = payload[4:]
            if _h == handle and pdu and pdu[0] == smp.PUBLIC_KEY:
                return pdu[1:]
        raise AssertionError("No Public Key PDU was sent.")

    def test_public_key_pdu_produces_our_key_and_a_queued_confirm_on_the_wire(self):
        link, _server, _input_report, transport = self._connected()
        handle = link.connected_handle

        link.pump(smp_acl_packet(handle, sc_pairing_request_pdu()))
        transport.sent.clear()

        _peer_private, peer_public_key = crypto.generate_p256_keypair()
        link.pump(smp_acl_packet(handle, bytes([smp.PUBLIC_KEY]) + peer_public_key))

        smp_frames = [p[4:] for h, p in transport.sent if h == handle]
        opcodes = [frame[0] for frame in smp_frames]
        assert opcodes == [smp.PUBLIC_KEY, smp.PAIRING_CONFIRM]

        our_public = smp_frames[0][1:]
        assert len(our_public) == 64
        x = int.from_bytes(our_public[:32], "little")
        y = int.from_bytes(our_public[32:], "little")
        assert crypto._p256_on_curve(x, y)

    def test_full_exchange_completes_and_encrypts_without_legacy_key_distribution(self):
        link, server, _input_report, transport = self._connected()
        handle = link.connected_handle

        peer_local_address = bytes([0xAA] * 6)  # matches connection_complete_packet()
        peer_address_with_type = peer_local_address + bytes([0x00])
        own_address_with_type = link._local_address + bytes([0x00])

        preq = sc_pairing_request_pdu()
        link.pump(smp_acl_packet(handle, preq))

        # The initiator is a real P-256 party, so its public key is a valid
        # curve point and the DHKey below is a genuine shared secret.
        peer_private, peer_public_key = crypto.generate_p256_keypair()
        link.pump(smp_acl_packet(handle, bytes([smp.PUBLIC_KEY]) + peer_public_key))
        our_public = self._own_public_key_from_wire(transport, handle)
        dhkey = crypto.p256_compute_dhkey(peer_private, our_public)

        peer_random = bytes(range(16))
        link.pump(smp_acl_packet(handle, bytes([smp.PAIRING_RANDOM]) + peer_random))
        own_random = [p for h, p in transport.sent if h == handle][-1][4:][1:]

        mackey, ltk = crypto.f5(
            fake_hardware_encrypt, dhkey, peer_random, own_random,
            peer_address_with_type, own_address_with_type,
        )
        peer_check = crypto.f6(
            fake_hardware_encrypt, mackey, peer_random, own_random, smp._DHKEY_CHECK_R,
            preq[1:4], peer_address_with_type, own_address_with_type,
        )
        link.pump(smp_acl_packet(handle, bytes([smp.DHKEY_CHECK]) + peer_check))

        assert link._security.state is smp.State.AWAITING_ENCRYPTION
        assert link._security.short_term_key == ltk

        link.pump(encryption_change_packet(handle=handle, enabled=True))
        assert server.encrypted
        assert link._bond.ltk == ltk

        smp_frames = [p[4:5] for h, p in transport.sent if h == handle]
        assert bytes([smp.ENCRYPTION_INFORMATION]) not in smp_frames
        assert bytes([smp.MASTER_IDENTIFICATION]) not in smp_frames

