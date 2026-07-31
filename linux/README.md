# blekeyboard (Linux)

Linux implementation of `blekeyboard`, using BlueZ's HCI user channel to obtain raw access to a local Bluetooth controller.

See [`../windows`](../windows) for the Windows implementation. The HCI packet construction layer (`emulator.py`) is common to both platforms; only the transport layer (`hijack.py`) differs.

## Project status

Alpha, and currently ahead of the Windows implementation. Verified against real hardware: the controller is claimed, reset and configured, advertises a discoverable name, accepts an incoming connection, serves a GATT attribute table that a client can discover and read, and pairs with the peer to encrypt the link. The HID layer is in development, so a connected device cannot yet receive keystrokes.

Pairing implements LE Legacy with the Just Works association model, the only one available to a device with no display and no keypad. It leaves an established session safe from passive eavesdropping but offers no protection against an attacker present during pairing. Keys are not retained, so each connection pairs again. AES is performed by the controller through the LE Encrypt command, which is what allows the implementation to stay free of a cryptography dependency. See the [project roadmap](../README.md#roadmap).

## How it works

Windows requires replacing the vendor driver with WinUSB to reach the controller. Linux exposes equivalent access natively through BlueZ's HCI user channel: binding an `AF_BLUETOOTH` / `BTPROTO_HCI` socket with `HCI_CHANNEL_USER` grants exclusive raw HCI command and event access, detaching the adapter from `bluetoothd` and the kernel Bluetooth stack for as long as the socket remains open.

As a result, the Linux implementation has no external dependencies and communicates with the adapter using only the Python standard library `socket` module.

## Requirements

- Python 3.10 or later
- A Bluetooth Low Energy 4.2 or later controller recognised by BlueZ, listed as `hci0`, `hci1`, and so on by `bluetoothctl list` or `btmgmt info`
- `CAP_NET_ADMIN`, granted either by running as root or by assigning the capability to the interpreter

## Installation

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

Alternatively, grant the capability to the interpreter to avoid running the process fully privileged:

```bash
sudo setcap cap_net_admin+eip $(readlink -f $(which python3))
```

### Command line

```bash
sudo python -m blekeyboard
```

Starts the advertising service and holds the adapter until interrupted with `Ctrl+C`.

### Library

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

### API reference

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
| `BLEBroadcaster.set_advertising_payload(name)` | Sets advertising data to flags and the complete local name, up to 26 bytes. |
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

This project is intended for educational and experimental use. Behaviour depends heavily on controller and driver support and may vary across hardware and operating system configurations.
