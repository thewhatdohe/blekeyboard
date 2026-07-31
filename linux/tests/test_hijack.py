import socket

import pytest

from blekeyboard.hci import HCI_COMMAND_PKT
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
        transport.read_event_packet()


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
    assert transport.read_event_packet(timeout_ms=1) == []


def test_read_propagates_real_socket_errors():
    class FailingSocket:
        def settimeout(self, _):
            pass

        def recv(self, _):
            raise OSError(5, "Input/output error")

    transport = HCITransport(dev_id=0)
    transport.sock = FailingSocket()
    with pytest.raises(OSError):
        transport.read_event_packet(timeout_ms=1)
