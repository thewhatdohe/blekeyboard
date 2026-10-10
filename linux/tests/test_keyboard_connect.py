"""
Exercises the one seam test_keyboard.py's StubLink bypasses: the real
background thread started by connect(), reading through a fake transport
that never claims a real socket.

This is the only place the threading and locking in Keyboard actually run,
so it is worth covering even without hardware.
"""
import threading

import pytest

from blekeyboard.keyboard import Keyboard


class FakeHCITransport:
    """Enough of HCITransport's surface for Link.initialize() and the pump
    loop to run without ever touching a real socket."""

    def __init__(self, dev_id=0):
        self.dev_id = dev_id
        self.max_acl_payload = 27
        self.total_acl_credits = 0
        self.available_acl_credits = 0
        self.connected = False
        self.released = threading.Event()
        self.read_raises = None

    def connect(self):
        self.connected = True

    def send_control_packet(self, packet):
        pass

    def send_acl_payload(self, handle, payload):
        return 1

    def configure_acl_buffers(self, payload_length, total_packets):
        pass

    def credit_acl_packets(self, count):
        pass

    def read_packet(self, timeout_ms=200):
        if self.read_raises is not None:
            raise self.read_raises
        # Nothing ever arrives; a real controller would deliver Command
        # Complete events here, but Link.initialize() does not block on them.
        return []

    def release(self):
        self.connected = False
        self.released.set()


@pytest.fixture
def keyboard(monkeypatch):
    monkeypatch.setattr("blekeyboard.keyboard.HCITransport", FakeHCITransport)
    # No bond store, so the background thread never touches the real state
    # directory; bond persistence has its own tests.
    return Keyboard(bond_store=None)


class TestConnectLifecycle:
    def test_connect_times_out_when_no_host_ever_subscribes(self, keyboard):
        # Nothing in this test ever sends a connection event, so readiness
        # can never be reached; this proves the timeout path itself works
        # rather than hanging forever.
        assert keyboard.connect(timeout=0.3) is False

    def test_background_thread_is_running_after_connect(self, keyboard):
        keyboard.connect(timeout=0.2)
        assert keyboard._thread.is_alive()
        keyboard.disconnect()

    def test_disconnect_stops_the_background_thread(self, keyboard):
        keyboard.connect(timeout=0.2)
        keyboard.disconnect()
        assert not keyboard._thread.is_alive()

    def test_disconnect_releases_the_transport(self, keyboard):
        keyboard.connect(timeout=0.2)
        transport = keyboard._transport
        keyboard.disconnect()
        assert transport.released.is_set()

    def test_is_connected_is_false_when_nobody_ever_paired(self, keyboard):
        keyboard.connect(timeout=0.2)
        assert not keyboard.is_connected()
        keyboard.disconnect()

    def test_disconnect_before_connect_does_not_raise(self):
        Keyboard().disconnect()


class TestBackgroundThreadFailure:
    """
    If the background thread dies, a caller must find out rather than the
    script hanging or silently doing nothing forever.
    """

    def test_a_crashed_background_thread_is_recorded(self, keyboard):
        keyboard.connect(timeout=0.1)
        keyboard._transport.read_raises = RuntimeError("simulated controller fault")

        keyboard._thread.join(timeout=1.0)
        assert not keyboard._thread.is_alive()
        assert isinstance(keyboard.background_error, RuntimeError)
        keyboard.disconnect()

    def test_is_connected_raises_once_the_background_thread_has_died(self, keyboard):
        keyboard.connect(timeout=0.1)
        keyboard._transport.read_raises = RuntimeError("simulated controller fault")
        keyboard._thread.join(timeout=1.0)

        with pytest.raises(RuntimeError, match="Background link thread"):
            keyboard.is_connected()
        keyboard.disconnect()

    def test_press_raises_once_the_background_thread_has_died(self, keyboard):
        keyboard.connect(timeout=0.1)
        keyboard._transport.read_raises = RuntimeError("simulated controller fault")
        keyboard._thread.join(timeout=1.0)

        with pytest.raises(RuntimeError, match="Background link thread"):
            keyboard.press("a")
        keyboard.disconnect()

    def test_healthy_thread_reports_no_background_error(self, keyboard):
        keyboard.connect(timeout=0.2)
        assert keyboard.background_error is None
        keyboard.disconnect()
