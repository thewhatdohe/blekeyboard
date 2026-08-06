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

from blekeyboard.bonds import BondStore
from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.gatt import GattServer
from blekeyboard.hijack import HCITransport
from blekeyboard.keycodes import (
    KEY_BACKSPACE,
    KEY_CAPS_LOCK,
    KEY_DELETE,
    KEY_DOWN_ARROW,
    KEY_END,
    KEY_ENTER,
    KEY_ESCAPE,
    KEY_F1,
    KEY_F2,
    KEY_F3,
    KEY_F4,
    KEY_F5,
    KEY_F6,
    KEY_F7,
    KEY_F8,
    KEY_F9,
    KEY_F10,
    KEY_F11,
    KEY_F12,
    KEY_HOME,
    KEY_INSERT,
    KEY_LEFT_ALT,
    KEY_LEFT_ARROW,
    KEY_LEFT_CTRL,
    KEY_LEFT_GUI,
    KEY_LEFT_SHIFT,
    KEY_PAGE_DOWN,
    KEY_PAGE_UP,
    KEY_PAUSE,
    KEY_PRINT_SCREEN,
    KEY_RIGHT_ARROW,
    KEY_SCROLL_LOCK,
    KEY_SPACE,
    KEY_TAB,
    KEY_UP_ARROW,
    keycode_for_char,
    modifier_bit_for,
)
from blekeyboard.link import Link
from blekeyboard.profile import build_database

DEFAULT_DEVICE_NAME = "BLE-Ducky"

# How long a key is held before its release report is sent, and the gap
# before the next character starts. Both matter relative to the connection
# interval the central negotiates - Link now logs it on every connection -
# since a report sent faster than that interval allows onto the air is at
# the mercy of however the host's stack buffers or coalesces the backlog.
# 30ms gives real margin above the intervals phones typically negotiate
# (often in the 15-50ms range) without making typing perceptibly slow.
KEY_HOLD_SECONDS = 0.03
INTER_CHARACTER_SECONDS = 0.03



class Keyboard:
    """A BLE HID keyboard, controlled synchronously from a script."""

    # Convenience aliases for the modifier keys, so scripts read the way an
    # ESP32-BLE-Keyboard payload does rather than naming the raw keycode.
    KEY_CTRL = KEY_LEFT_CTRL
    KEY_SHIFT = KEY_LEFT_SHIFT
    KEY_ALT = KEY_LEFT_ALT
    KEY_GUI = KEY_LEFT_GUI

    # Non-modifier named keys with no character of their own, re-exported
    # from keycodes.py so a script can write Keyboard.KEY_ENTER instead of
    # importing the keycodes module separately just to name one key. tap()
    # is the method meant for these - it presses and releases cleanly,
    # unlike press(), which holds a key until a separate release() call.
    KEY_ENTER = KEY_ENTER
    KEY_ESCAPE = KEY_ESCAPE
    KEY_BACKSPACE = KEY_BACKSPACE
    KEY_TAB = KEY_TAB
    KEY_SPACE = KEY_SPACE
    KEY_CAPS_LOCK = KEY_CAPS_LOCK
    KEY_PRINT_SCREEN = KEY_PRINT_SCREEN
    KEY_SCROLL_LOCK = KEY_SCROLL_LOCK
    KEY_PAUSE = KEY_PAUSE
    KEY_INSERT = KEY_INSERT
    KEY_HOME = KEY_HOME
    KEY_PAGE_UP = KEY_PAGE_UP
    KEY_DELETE = KEY_DELETE
    KEY_END = KEY_END
    KEY_PAGE_DOWN = KEY_PAGE_DOWN
    KEY_RIGHT_ARROW = KEY_RIGHT_ARROW
    KEY_LEFT_ARROW = KEY_LEFT_ARROW
    KEY_DOWN_ARROW = KEY_DOWN_ARROW
    KEY_UP_ARROW = KEY_UP_ARROW
    KEY_F1 = KEY_F1
    KEY_F2 = KEY_F2
    KEY_F3 = KEY_F3
    KEY_F4 = KEY_F4
    KEY_F5 = KEY_F5
    KEY_F6 = KEY_F6
    KEY_F7 = KEY_F7
    KEY_F8 = KEY_F8
    KEY_F9 = KEY_F9
    KEY_F10 = KEY_F10
    KEY_F11 = KEY_F11
    KEY_F12 = KEY_F12

    def __init__(self, device_name: str = DEFAULT_DEVICE_NAME, dev_id: int = 0, log=None,
                 bond_store="default"):
        self._device_name = device_name
        self._dev_id = dev_id
        self._log = log or (lambda _message: None)

        # Persist bonds by default so a host reconnecting after a restart
        # resumes without pairing again. Pass bond_store=None to keep keys
        # off disk, or a BondStore with a chosen path to place them elsewhere.
        self._bond_store = BondStore() if bond_store == "default" else bond_store

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
            bond_store=self._bond_store,
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

    @property
    def host_guess(self):
        """
        A best-effort HostGuess for the connected peer - see hostprofile.py
        for exactly what this can and cannot tell you. None before any
        connection has been attempted.
        """
        self._check_background_error()
        return self._link.host_guess if self._link is not None else None

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

    def tap(self, *keys):
        """
        Presses a combination and releases it the way a physical keyboard
        does: one transition at a time, the ordinary keys lifted before the
        modifiers.

        Releasing a modifier and a key in the same report - clearing the
        modifier byte and the key array at once - is what several hosts, iOS
        among them, mishandle, leaving the modifier stuck so that every tap
        becomes a modifier-click and the host is barely usable. Lifting the
        keys first, then the modifiers, then sending a final all-clear (twice,
        so a single dropped report still cannot strand a modifier) mirrors
        real hardware and releases cleanly.
        """
        resolved = [(self._resolve(key), key) for key in keys]
        modifiers = [key for (bits, code), key in resolved if bits and not code]
        ordinary = [key for (bits, code), key in resolved if code]

        self.press(*keys)
        time.sleep(KEY_HOLD_SECONDS)
        if ordinary:
            self.release(*ordinary)   # keys up, modifiers still held
        if modifiers:
            self.release(*modifiers)  # then the modifiers
        self.release_all()
        self.release_all()

    def switch_input_language(self):
        """
        Cycles the host's hardware-keyboard input language, for a host whose
        active layout is not the one a payload was written for.

        A HID keyboard sends physical key positions, not characters, so it
        can never choose the host's layout itself - iOS ignores the HID
        country code entirely. What it can do is send the shortcut the host
        uses to switch: on iOS that is Ctrl+Space, and it only takes effect
        while a text field is focused. A host sitting on the wrong language
        (typing, say, Arabic for a US-layout payload) is switched a step at a
        time, so call this once per language between the target and the one
        wanted, with a field focused.
        """
        self.tap(self.KEY_CTRL, " ")

    def write(self, char: str):
        """
        Presses and releases a single character.

        The key is pressed with any modifier it needs, then the key is lifted
        before the modifier, so a modifier is never cleared in the same report
        as its key - the transition that otherwise strands a modifier on the
        host and leaves it acting as though a key is held.

        Independent of any combination held through press(): the held state is
        preserved and restored around this one keystroke, so a script is free
        to mix write() with press()-held modifiers.
        """
        if len(char) != 1:
            raise ValueError(f"write() takes a single character, got {char!r}.")

        self._check_background_error()
        modifier, keycode = keycode_for_char(char)
        with self._io_lock:
            combined = self._held_modifier | modifier

            self._require_sent(combined, self._held_keycodes + [keycode])
            time.sleep(KEY_HOLD_SECONDS)

            # Key up while the modifier is still held, then back to the held
            # state, so a modifier is never cleared in the same report as its
            # key - the transition that otherwise strands it on the host.
            if modifier & ~self._held_modifier:
                self._link.send_key_report(combined, self._held_keycodes)
            self._link.send_key_report(self._held_modifier, self._held_keycodes)

    def _require_sent(self, modifier, keycodes):
        if not self._link.send_key_report(modifier, keycodes):
            raise RuntimeError("No host is currently connected and subscribed.")

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

    def _reassert_on_ready(self, was_ready: bool) -> bool:
        """
        Re-sends the intended key state each time the host becomes ready.

        Called with the caller's lock already held. On a first connection or
        a reconnect resuming a bond, the host and this side must agree on what
        is held. Normally nothing is, so this sends an all-keys-up report that
        clears any key the host still believes is down from before a drop or a
        disconnect; if a combination is deliberately held, it re-presses it.
        Returns the current readiness, for the caller to carry into the next
        check.
        """
        ready = self._link.is_ready
        if ready and not was_ready:
            self._link.send_key_report(self._held_modifier, self._held_keycodes)
        return ready

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
        was_ready = False
        while not self._stop.is_set():
            try:
                with self._io_lock:
                    packet = self._transport.read_packet(timeout_ms=200)
                    if packet:
                        self._link.pump(packet)

                    was_ready = self._reassert_on_ready(was_ready)

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
