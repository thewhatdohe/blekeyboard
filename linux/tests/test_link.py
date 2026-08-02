from blekeyboard import att, smp
from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.gatt import GattServer
from blekeyboard.hci import parse_acl
from blekeyboard.l2cap import L2CAPReassembler
from blekeyboard.link import Link
from blekeyboard.profile import build_database

OPCODE_LE_RAND = 0x2018


class RecordingTransport:
    """
    A transport stub that records outbound ACL payloads.

    Also answers LE Rand with a synthetic Command Complete event, since
    bond key generation needs the controller round trip to actually
    complete rather than hang waiting for a reply that never comes.
    """

    def __init__(self):
        self.sent = []
        self.control_packets = []
        self.max_acl_payload = 27
        self.total_acl_credits = 0
        self.available_acl_credits = 0
        self._queued_events = []
        self._rand_calls = 0

    def send_control_packet(self, packet):
        self.control_packets.append(packet)
        # Packet layout is [opcode_lo, opcode_hi, length, *data], per
        # BLEBroadcaster._build_hci_packet - no leading H4 byte here, since
        # that framing is added inside the real transport, not by the caller.
        opcode = packet[0] | (packet[1] << 8)
        if opcode == OPCODE_LE_RAND:
            self._rand_calls += 1
            rand = bytes(((self._rand_calls * 37 + i) & 0xFF) for i in range(8))
            params = [0x01] + [opcode & 0xFF, opcode >> 8] + [0x00] + list(rand)
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


def make_link():
    transport = RecordingTransport()
    broadcaster = BLEBroadcaster(transport)
    database, input_report = build_database("BLE-Ducky")
    server = GattServer(database)
    link = Link(transport, broadcaster, server, input_report, "BLE-Ducky", log=lambda _m: None)
    return link, server, input_report, transport


def connection_complete_packet(handle=0x0010):
    """A raw LE Connection Complete event, peripheral role, public address."""
    return (
        [0x04, 0x3E, 0x13, 0x01, 0x00]
        + list(handle.to_bytes(2, "little"))
        + [0x01, 0x00] + [0xAA] * 6
        + [0x18, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00]
    )


def disconnection_complete_packet(handle=0x0010, reason=0x13):
    return [0x04, 0x05, 0x04, 0x00] + list(handle.to_bytes(2, "little")) + [reason]


def encryption_change_packet(handle=0x0010, enabled=True, status=0x00):
    return [0x04, 0x08, 0x04, status] + list(handle.to_bytes(2, "little")) + [1 if enabled else 0]


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

        report = pdu[3:]
        assert report[1] == 0x02          # modifier
        assert report[3] == 0x04          # first keycode

    def test_attribute_value_is_updated_for_a_subsequent_read(self):
        link, server, input_report, _transport = make_link()
        link.pump(connection_complete_packet())
        server.encrypted = True
        subscribe(server, input_report)

        link.send_key_report(0x00, [0x05])
        assert input_report.value[3] == 0x05


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

