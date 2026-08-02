"""
The scripting API: a BLE keyboard driven from Python, styled after T-vK's
ESP32-BLE-Keyboard so a payload written against that library is easy to
carry over.

    from blekeyboard import Keyboard

    keyboard = Keyboard()
    keyboard.connect()
    keyboard.press(Keyboard.KEY_GUI, "r")
    keyboard.release_all()
    time.sleep(0.5)
    keyboard.print("notepad\\n")

`connect()` blocks until a host has paired and subscribed to notifications,
since nothing sent before that point would go anywhere. Everything runs a
background thread that owns the connection; the methods below only ever
touch it through `Link`, which is written to be safe to drive from one
thread while being read from another.
"""

import threading
import time

from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.gatt import GattServer
from blekeyboard.hijack import HCITransport
from blekeyboard.keycodes import (
    KEY_LEFT_ALT,
    KEY_LEFT_CTRL,
    KEY_LEFT_GUI,
    KEY_LEFT_SHIFT,
    keycode_for_char,
    modifier_bit_for,
)
from blekeyboard.link import Link
from blekeyboard.profile import build_database

DEFAULT_DEVICE_NAME = "BLE-Ducky"

# How long a key is held before its release report is sent. HID hosts debounce
# on the report boundary, not on time, so this only needs to be long enough
# that down and up are unambiguously two separate reports.
KEY_HOLD_SECONDS = 0.015

# Gap between characters in write()/print(). Zero works against most hosts;
# this exists for the ones that drop keystrokes typed faster than a human can.
INTER_CHARACTER_SECONDS = 0.0


class Keyboard:
    """A BLE HID keyboard, controlled synchronously from a script."""

    # Convenience aliases for the modifier keys, so scripts read the way an
    # ESP32-BLE-Keyboard payload does rather than naming the raw keycode.
    KEY_CTRL = KEY_LEFT_CTRL
    KEY_SHIFT = KEY_LEFT_SHIFT
    KEY_ALT = KEY_LEFT_ALT
    KEY_GUI = KEY_LEFT_GUI

    def __init__(self, device_name: str = DEFAULT_DEVICE_NAME, dev_id: int = 0, log=None):
        self._device_name = device_name
        self._dev_id = dev_id
        self._log = log or (lambda _message: None)

        self._transport = None
        self._link = None
        self._thread = None
        self._stop = threading.Event()
        self._io_lock = threading.Lock()
        self.background_error = None

        # Keys currently understood to be held down, maintained across
        # press()/release() calls so a caller can build up a combination.
        self._held_modifier = 0
        self._held_keycodes = []

    def connect(self, timeout: float = None) -> bool:
        """
        Brings the adapter up, advertises, and waits for a host to pair and
        subscribe to notifications.

        Returns whether that happened within `timeout` seconds. With no
        timeout, waits indefinitely, since a pentest payload is typically
        run and left to wait for a target to accept pairing.
        """
        self._transport = HCITransport(dev_id=self._dev_id)
        self._transport.connect()

        database, input_report = build_database(self._device_name)
        server = GattServer(database)
        self._link = Link(
            self._transport, BLEBroadcaster(self._transport), server,
            input_report, self._device_name, log=self._log,
        )
        self._link.initialize()

        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

        deadline = None if timeout is None else time.time() + timeout
        while deadline is None or time.time() < deadline:
            self._check_background_error()
            if self._link.is_ready:
                return True
            time.sleep(0.05)
        return self._link.is_ready

    def is_connected(self) -> bool:
        """Whether a host is currently paired and subscribed to reports."""
        self._check_background_error()
        return self._link is not None and self._link.is_ready

    def disconnect(self):
        """Stops advertising and the background thread, releasing the adapter."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._link is not None:
            self._link.shutdown()
        if self._transport is not None:
            self._transport.release()

    def press(self, *keys):
        """
        Adds each key to the held set and sends the resulting report.

        A key is a single character, resolved through the US layout table, or
        a raw keycode such as one of the `Keyboard.KEY_*` constants. A
        modifier keycode is folded into the modifier byte rather than the
        keycode array, matching how a real keyboard reports it.
        """
        for key in keys:
            modifier, keycode = self._resolve(key)
            self._held_modifier |= modifier
            if keycode and keycode not in self._held_keycodes:
                if len(self._held_keycodes) >= 6:
                    raise ValueError("At most six non-modifier keys may be held at once.")
                self._held_keycodes.append(keycode)
        self._send_held_state()

    def release(self, *keys):
        """Removes each key from the held set and sends the resulting report."""
        for key in keys:
            modifier, keycode = self._resolve(key)
            self._held_modifier &= ~modifier
            if keycode in self._held_keycodes:
                self._held_keycodes.remove(keycode)
        self._send_held_state()

    def release_all(self):
        """Releases every held key, sending the all-zero report."""
        self._held_modifier = 0
        self._held_keycodes = []
        self._send_held_state()

    def write(self, char: str):
        """
        Presses and releases a single character.

        Independent of any combination held through press(): the held state
        is preserved and restored around this one keystroke, so a script is
        free to mix write() with press()-held modifiers.
        """
        if len(char) != 1:
            raise ValueError(f"write() takes a single character, got {char!r}.")

        self._check_background_error()
        modifier, keycode = keycode_for_char(char)
        with self._io_lock:
            if not self._link.send_key_report(self._held_modifier | modifier, [keycode]):
                raise RuntimeError("No host is currently connected and subscribed.")
            time.sleep(KEY_HOLD_SECONDS)
            self._link.send_key_report(self._held_modifier, self._held_keycodes)

    def print(self, text: str):
        """Types a string one character at a time via write()."""
        for char in text:
            self.write(char)
            if INTER_CHARACTER_SECONDS:
                time.sleep(INTER_CHARACTER_SECONDS)

    # print() is the T-vK name; type() reads more naturally from Python.
    type = print

    def _resolve(self, key):
        """Turns a press()/release() argument into (modifier_bits, keycode)."""
        if isinstance(key, str):
            if len(key) != 1:
                raise ValueError(f"A key must be a single character, got {key!r}.")
            return keycode_for_char(key)

        keycode = int(key)
        modifier_bit = modifier_bit_for(keycode)
        if modifier_bit is not None:
            return modifier_bit, 0
        return 0, keycode

    def _send_held_state(self):
        self._check_background_error()
        with self._io_lock:
            if not self._link.send_key_report(self._held_modifier, self._held_keycodes):
                raise RuntimeError("No host is currently connected and subscribed.")

    def _run(self):
        """
        Background loop: pumps packets and sends the periodic keepalive.

        An uncaught exception here would otherwise kill this thread silently,
        leaving `connect()`/`is_connected()` reporting stale state forever
        with no indication anything had gone wrong. Instead this is recorded
        on `self.background_error` and re-raised the next time a foreground
        method is called, so a caller finds out promptly rather than staring
        at a script that has quietly stopped doing anything.
        """
        last_keepalive = time.time()
        while not self._stop.is_set():
            try:
                with self._io_lock:
                    packet = self._transport.read_packet(timeout_ms=200)
                    if packet:
                        self._link.pump(packet)

                    if time.time() - last_keepalive >= 10.0:
                        self._link.send_keepalive()
                        last_keepalive = time.time()
            except Exception as error:
                self._log(f"Background link thread stopped: {error!r}")
                self.background_error = error
                return

    def _check_background_error(self):
        if self.background_error is not None:
            raise RuntimeError(
                "Background link thread has stopped; see .background_error."
            ) from self.background_error
