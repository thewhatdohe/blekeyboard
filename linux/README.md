# blekeyboard (Linux)

Linux implementation of `blekeyboard`, using BlueZ's HCI user channel to obtain raw access to a local Bluetooth controller.

See [`../windows`](../windows) for the Windows implementation. The HCI packet construction layer (`emulator.py`) is common to both platforms; only the transport layer (`hijack.py`) differs.

## Project status

Alpha. Advertising is implemented and verified against real hardware: the controller is claimed, reset, configured, and broadcasts a discoverable device name. The GATT, pairing, and HID layers are in development, so a connecting device will find no services and cannot receive keystrokes. See the [project roadmap](../README.md#roadmap).

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
| `HCITransport.read_event_packet(timeout_ms)` | Reads an HCI event packet, returning an empty list on timeout. |
| `HCITransport.release()` | Closes the socket and returns the adapter to the kernel. |
| `BLEBroadcaster.reset_controller()` | Issues HCI Reset. Required after claiming the adapter. |
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
