# blekeyboard (Linux)

Linux implementation of `blekeyboard`, using BlueZ's HCI user channel to obtain raw access to a local Bluetooth controller.

See [`../windows`](../windows) for the Windows implementation. The HCI packet construction layer (`emulator.py`) is common to both platforms; only the transport layer (`hijack.py`) differs.

## Project status

Alpha, and currently the only functional implementation - the Windows package is an early transport-layer prototype and cannot yet pair or type. The full stack is implemented and verified against real hardware: the controller is claimed, reset and configured, advertises as a discoverable HID keyboard, is paired through the host operating system's own Bluetooth settings, enrols as a keyboard via HID over GATT, and delivers key reports over the encrypted link. This has been confirmed end to end on iOS, including actual on-screen typing, not just a successfully encrypted link.

Pairing implements both LE Legacy and LE Secure Connections, both restricted to the Just Works association model - the only one available to a device with no display and no keypad. Whichever a peer offers is used automatically; SC is preferred when available and is what several hosts, iOS included, require before treating the peripheral as a genuinely trusted input device rather than merely an encrypted one. The ECDH key agreement SC needs runs in pure Python rather than through the controller's own P-256/DHKey commands, since at least one common controller wedges its command queue partway through that exchange; AES still runs through the controller's LE Encrypt command. Neither adds a runtime dependency. A formed bond is persisted to `~/.local/state/blekeyboard/bonds.json` (owner-readable only), so a host reconnecting after this process restarts resumes the encrypted session without pairing again.

A host will always prompt to confirm pairing with a new device before accepting input from it; this is a platform-level gate BLE HID has no way around. See the [project roadmap](../README.md#roadmap) and the BLE injection limitation noted there.

## How it works

Windows requires replacing the vendor driver with WinUSB to reach the controller. Linux exposes equivalent access natively through BlueZ's HCI user channel: binding an `AF_BLUETOOTH` / `BTPROTO_HCI` socket with `HCI_CHANNEL_USER` grants exclusive raw HCI command and event access, detaching the adapter from `bluetoothd` and the kernel Bluetooth stack for as long as the socket remains open.

As a result, the Linux implementation has no external dependencies and communicates with the adapter using only the Python standard library (`socket` for the transport, `secrets` for cryptographic randomness).

## Requirements

- Python 3.10 or later
- A Bluetooth Low Energy 4.2 or later controller recognised by BlueZ, listed as `hci0`, `hci1`, and so on by `bluetoothctl list` or `btmgmt info`
- `CAP_NET_ADMIN`, granted either by running as root or by assigning the capability to the interpreter

## Installation

```bash
pip install blekeyboard
```

For a local checkout instead:

```bash
pip install -e .
```

## Usage

### Preparing the adapter

The HCI user channel requires the target adapter to be down before it can be claimed:

```bash
sudo btmgmt --index 0 power off
```

This suspends normal Bluetooth functionality on that adapter, including connected peripherals such as mice and headsets, until it is restored.

> **Note**
> Older documentation refers to `sudo hciconfig hci0 down`. The `hciconfig` and `hcitool` utilities are deprecated and no longer shipped with current BlueZ releases; use `btmgmt` or `bluetoothctl power off` instead.

### Granting permissions

Run as root:

```bash
sudo python3 -m blekeyboard
```

Alternatively, grant the capability to the interpreter to avoid running the process fully privileged. Do this against a virtual environment's own interpreter, not a shared system Python: `setcap` targets a specific binary, and a venv created with `--copies` (not the default symlink) gets its own physical copy, so the grant does not extend to every other script that Python ever runs.

```bash
python3 -m venv --copies ~/.venvs/blekeyboard
~/.venvs/blekeyboard/bin/pip install blekeyboard
sudo setcap cap_net_admin+eip ~/.venvs/blekeyboard/bin/python3
~/.venvs/blekeyboard/bin/python3 -m blekeyboard
```

### Command line

```bash
sudo python -m blekeyboard
```

Advertises as a keyboard and waits for a host to pair and subscribe, then drops into an interactive prompt: `Enter` types a demonstration string, `t <text>` types anything else, `run <path>` runs a Ducky Script file, `who` prints a best-effort guess at the connected host's OS, `l` sends the iOS input-language-switch shortcut, and `r` releases every key (useful if a host still believes one is held after a dropped notification). Holds the adapter until interrupted with `Ctrl+C`.

### Scripting API

```python
from blekeyboard import Keyboard

keyboard = Keyboard()
keyboard.connect()  # blocks until a host has paired and subscribed

keyboard.press(Keyboard.KEY_GUI, "r")  # open Run on Windows
keyboard.release_all()

keyboard.print("notepad\n")
```

`connect()` brings the adapter up, advertises, and blocks until a host has paired and subscribed to notifications; pass `timeout=` to give up after a limited wait instead of blocking indefinitely. `press()`/`release()` accept single characters or raw keycodes such as the `Keyboard.KEY_*` modifier constants, and accumulate into a held combination across calls. `write()` types one character; `print()` (aliased as `type()`) types a string.

#### API reference

| Method | Description |
| --- | --- |
| `Keyboard.connect(timeout=None)` | Brings up the adapter, advertises, and waits for a host to pair and subscribe. Returns whether that happened. |
| `Keyboard.is_connected()` | Whether a host is currently paired and subscribed. |
| `Keyboard.disconnect()` | Stops advertising and releases the adapter. |
| `Keyboard.press(*keys)` | Adds each key to the held combination and sends the resulting report. |
| `Keyboard.release(*keys)` | Removes each key from the held combination and sends the resulting report. |
| `Keyboard.release_all()` | Releases every held key. |
| `Keyboard.write(char)` | Presses and releases a single character, preserving any keys held via `press()`. |
| `Keyboard.print(text)` / `Keyboard.type(text)` | Types a string one character at a time. |
| `Keyboard.tap(*keys)` | Presses a combination, then releases it the way physical hardware sequences a keystroke - ordinary keys before modifiers - so a dropped notification can't strand a modifier on the host. |
| `Keyboard.switch_input_language()` | Sends Ctrl+Space, the iOS shortcut to cycle the hardware-keyboard input language. A HID keyboard can only send key positions, never choose the host's layout - iOS ignores the HID country code entirely - so this is the only lever available when the host's active layout doesn't match the payload. |
| `Keyboard.host_guess` | A best-effort `HostGuess` for the connected peer - see [Host detection](#host-detection) below. `None` before any connection. |

### Ducky Script

A second, deliberately restricted input syntax alongside the scripting API above, styled after the USB Rubber Ducky's payload format:

```python
from blekeyboard import Keyboard, run_duckyscript

keyboard = Keyboard()
keyboard.connect()

run_duckyscript(keyboard, """
    REM opens a run dialog and types a command
    STRINGLN notepad.exe
    DELAY 500
    STRING done
""")
```

Supported, one command per line: `STRING`/`STRINGLN <text>`, `DELAY <milliseconds>`, `REM <comment>`, and single named keys on their own line (`ENTER`, `TAB`, `ESCAPE`, the arrow keys, `F1`-`F12`, and similar). Key combinations (`GUI r`, `CTRL ALT DEL`) and a key held across lines (`HOLD`/`RELEASE`) are not implemented yet; a line naming one raises `DuckyScriptError` rather than being silently misinterpreted. `run_duckyscript_file(keyboard, path)` reads and runs a script from disk - this is what the CLI's `run <path>` command uses.

### Host detection

`Keyboard.host_guess` returns a `HostGuess` - a `HostOS` (`IOS`, `ANDROID`, `WINDOWS`, `MACOS`, `LINUX`, or `UNKNOWN`), a `confidence` (`"none"`, `"low"`, or `"medium"`, deliberately never higher), and `reasons` explaining the guess. This is necessarily a hint, not a fact: BLE has no field where a central announces its operating system, so this is inferred from a handful of observable signals during pairing (the peer's address type and its Pairing Request's `auth_req`/CT2 pattern) cross-referenced against per-platform tendencies this project has actually observed. Windows, Linux and macOS are not yet distinguishable from each other and are reported as `UNKNOWN` rather than guessed at random.

### Low-level API

The scripting API is built on `HCITransport`, `BLEBroadcaster`, and `Link`, which remain available directly for anything the high-level API does not cover:

```python
import time

from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.hijack import HCITransport

transport = HCITransport(dev_id=0)
broadcaster = BLEBroadcaster(transport)

try:
    # Claim exclusive raw HCI access to the adapter.
    transport.connect()

    # A newly claimed controller is uninitialised and must be reset first.
    broadcaster.reset_controller()

    broadcaster.configure_advertising(interval_ms=400)
    broadcaster.set_advertising_payload("BLE-Ducky")
    broadcaster.set_state(enable=True)

    # Periodic informational queries keep the controller from idling.
    while True:
        time.sleep(10)
        broadcaster.send_keepalive_ping()

finally:
    broadcaster.set_state(enable=False)
    transport.release()
```

#### Low-level API reference

| Method | Description |
| --- | --- |
| `HCITransport.connect()` | Claims the adapter's HCI user channel. |
| `HCITransport.send_control_packet(packet)` | Writes an HCI command packet to the controller. |
| `HCITransport.send_acl_payload(handle, payload)` | Writes a payload to a connection, fragmenting it to the controller's ACL capacity. |
| `HCITransport.read_packet(timeout_ms)` | Reads one HCI packet of any type, returning an empty list on timeout. |
| `HCITransport.configure_acl_buffers(payload_length, total_packets)` | Adopts the ACL capacity reported by the controller. |
| `HCITransport.credit_acl_packets(count)` | Returns buffer slots released by a Number Of Completed Packets event. |
| `HCITransport.release()` | Closes the socket and returns the adapter to the kernel. |
| `BLEBroadcaster.reset_controller()` | Issues HCI Reset. Required after claiming the adapter. |
| `BLEBroadcaster.set_event_mask()` | Enables LE Meta event delivery, without which connection events are withheld. |
| `BLEBroadcaster.set_le_event_mask()` | Selects the LE subevents the controller reports. |
| `BLEBroadcaster.read_le_buffer_size()` | Queries the controller's ACL payload size and buffer count. |
| `BLEBroadcaster.read_bd_addr()` | Reads the controller's own public address, which pairing mixes into the confirm value. |
| `BLEBroadcaster.le_encrypt(key, plaintext)` | Runs one AES-128 block through the controller's engine. |
| `BLEBroadcaster.le_rand()` | Requests eight random octets from the controller. |
| `BLEBroadcaster.le_long_term_key_request_reply(handle, key)` | Supplies the key that encrypts a link. |
| `BLEBroadcaster.le_long_term_key_request_negative_reply(handle)` | Declines to supply a key, aborting encryption. |
| `BLEBroadcaster.configure_advertising(interval_ms)` | Sets advertising parameters. Accepts 20 ms to 10240 ms. |
| `BLEBroadcaster.set_advertising_payload(name, service_uuids=None)` | Sets advertising data: flags, the complete local name, and optionally a list of 16-bit service UUIDs. |
| `BLEBroadcaster.set_state(enable)` | Enables or disables advertising. |
| `BLEBroadcaster.send_keepalive_ping()` | Reads local version information as a controller liveness check. |

## Restoring normal Bluetooth operation

Closing the transport releases the user channel automatically. To return the adapter to BlueZ:

```bash
sudo btmgmt --index 0 power on
```

Normal desktop Bluetooth functionality resumes immediately; no reboot is required.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## Disclaimer

This project is intended for authorized security testing and research. Use it only against systems you own or have explicit written permission to test. Behaviour depends heavily on controller and driver support and may vary across hardware and operating system configurations.
