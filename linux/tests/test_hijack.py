import socket

import pytest

from blekeyboard.hci import (
    ACL_PB_CONTINUING,
    ACL_PB_FIRST,
    HCI_COMMAND_PKT,
    LE_MIN_ACL_PAYLOAD,
    parse_acl,
)
from blekeyboard.hijack import HCITransport


def test_platform_exposes_the_required_socket_constants():
    # The user channel is reached through a raw AF_BLUETOOTH HCI socket, so a
    # build of Python without these cannot host the transport at all.
    assert hasattr(socket, "AF_BLUETOOTH")
    assert hasattr(socket, "BTPROTO_HCI")


def test_transmitting_before_connecting_is_refused():
    transport = HCITransport(dev_id=0)
    with pytest.raises(RuntimeError, match="not established"):
        transport.send_control_packet([0x03, 0x0C, 0x00])


def test_receiving_before_connecting_is_refused():
    transport = HCITransport(dev_id=0)
    with pytest.raises(RuntimeError, match="not established"):
        transport.read_packet()


def test_sending_acl_before_connecting_is_refused():
    transport = HCITransport(dev_id=0)
    with pytest.raises(RuntimeError, match="not established"):
        transport.send_acl_payload(0x0040, b"\x01")


def test_release_is_safe_when_never_connected():
    # Winding down a transport that failed to connect must not raise, since
    # the entry point calls release unconditionally.
    HCITransport(dev_id=0).release()


def test_release_is_idempotent():
    transport = HCITransport(dev_id=0)
    transport.release()
    transport.release()
    assert transport.sock is None


def test_command_packets_are_framed_with_the_h4_indicator():
    # The H4 framing is prepended by the transport rather than the caller.
    sent = []

    class FakeSocket:
        def send(self, payload):
            sent.append(payload)

    transport = HCITransport(dev_id=0)
    transport.sock = FakeSocket()
    transport.send_control_packet([0x03, 0x0C, 0x00])

    assert sent == [bytes([HCI_COMMAND_PKT, 0x03, 0x0C, 0x00])]


def test_read_returns_empty_list_on_timeout():
    # A timeout means no data was ready, which is normal while idling and
    # must not surface as an error.
    class TimingOutSocket:
        def settimeout(self, _):
            pass

        def recv(self, _):
            raise TimeoutError

    transport = HCITransport(dev_id=0)
    transport.sock = TimingOutSocket()
    assert transport.read_packet(timeout_ms=1) == []


def test_read_propagates_real_socket_errors():
    class FailingSocket:
        def settimeout(self, _):
            pass

        def recv(self, _):
            raise OSError(5, "Input/output error")

    transport = HCITransport(dev_id=0)
    transport.sock = FailingSocket()
    with pytest.raises(OSError):
        transport.read_packet(timeout_ms=1)


class CollectingSocket:
    def __init__(self):
        self.sent = []

    def send(self, payload):
        self.sent.append(payload)


def _connected_transport():
    transport = HCITransport(dev_id=0)
    transport.sock = CollectingSocket()
    return transport


def test_acl_capacity_defaults_to_the_le_minimum():
    # Until the controller answers LE Read Buffer Size, assume only what
    # every controller is required to accept.
    assert HCITransport(dev_id=0).max_acl_payload == LE_MIN_ACL_PAYLOAD


def test_payload_within_capacity_is_sent_as_one_packet():
    transport = _connected_transport()
    assert transport.send_acl_payload(0x0040, b"\x01\x02\x03") == 1

    parsed = parse_acl(transport.sock.sent[0])
    assert parsed.handle == 0x0040
    assert parsed.packet_boundary == ACL_PB_FIRST
    assert parsed.data == b"\x01\x02\x03"


def test_oversized_payload_is_split_across_packets():
    transport = _connected_transport()
    transport.configure_acl_buffers(payload_length=4, total_packets=8)

    assert transport.send_acl_payload(0x0040, bytes(range(10))) == 3

    parsed = [parse_acl(p) for p in transport.sock.sent]
    assert [p.packet_boundary for p in parsed] == [
        ACL_PB_FIRST,
        ACL_PB_CONTINUING,
        ACL_PB_CONTINUING,
    ]
    # Reassembling the fragments must reproduce the original payload.
    assert b"".join(p.data for p in parsed) == bytes(range(10))


def test_reported_capacity_replaces_the_default():
    transport = HCITransport(dev_id=0)
    transport.configure_acl_buffers(payload_length=251, total_packets=12)
    assert transport.max_acl_payload == 251
    assert transport.available_acl_credits == 12


def test_shared_bredr_buffers_leave_the_payload_default_intact():
    # A reported length of zero means the controller has no dedicated LE
    # buffers, so the conservative default must stand.
    transport = HCITransport(dev_id=0)
    transport.configure_acl_buffers(payload_length=0, total_packets=0)
    assert transport.max_acl_payload == LE_MIN_ACL_PAYLOAD


def test_sending_consumes_controller_credits():
    transport = _connected_transport()
    transport.configure_acl_buffers(payload_length=27, total_packets=4)

    transport.send_acl_payload(0x0040, b"\x01")
    assert transport.available_acl_credits == 3


def test_exhausting_credits_is_refused_rather_than_overrunning():
    transport = _connected_transport()
    transport.configure_acl_buffers(payload_length=27, total_packets=1)

    transport.send_acl_payload(0x0040, b"\x01")
    with pytest.raises(RuntimeError, match="ACL buffer"):
        transport.send_acl_payload(0x0040, b"\x02")


def test_completed_packets_return_credits():
    transport = _connected_transport()
    transport.configure_acl_buffers(payload_length=27, total_packets=2)

    transport.send_acl_payload(0x0040, b"\x01")
    transport.credit_acl_packets(1)
    assert transport.available_acl_credits == 2


def test_credits_never_exceed_the_controller_total():
    transport = HCITransport(dev_id=0)
    transport.configure_acl_buffers(payload_length=27, total_packets=2)
    transport.credit_acl_packets(10)
    assert transport.available_acl_credits == 2


def test_credits_are_not_enforced_before_capacity_is_known():
    # Before LE Read Buffer Size is answered there is nothing to enforce, and
    # refusing to send would deadlock the handshake.
    transport = _connected_transport()
    transport.send_acl_payload(0x0040, b"\x01")
    assert len(transport.sock.sent) == 1
