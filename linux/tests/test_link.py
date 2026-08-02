from blekeyboard import att
from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.gatt import GattServer
from blekeyboard.hci import parse_acl
from blekeyboard.l2cap import L2CAPReassembler
from blekeyboard.link import Link
from blekeyboard.profile import build_database


class RecordingTransport:
    """A transport stub that records outbound ACL payloads."""

    def __init__(self):
        self.sent = []
        self.max_acl_payload = 27
        self.total_acl_credits = 0
        self.available_acl_credits = 0

    def send_control_packet(self, packet):
        pass

    def configure_acl_buffers(self, payload_length, total_packets):
        pass

    def credit_acl_packets(self, count):
        pass

    def send_acl_payload(self, handle, payload):
        self.sent.append((handle, payload))
        return 1

    def read_packet(self, timeout_ms=200):
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
