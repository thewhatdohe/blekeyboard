# blekeyboard (Linux, alpha)

`blekeyboard` is a Python package that allows you to emulate a wireless keyboard using Bluetooth Low Energy (BLE). It is inspired by the popular ESP32 library **ESP32-BLE-Keyboard** by T-vK, and aims to bring similar BLE HID keyboard functionality to Linux systems using native Bluetooth hardware.

This is the Linux port of `blekeyboard`. See [`../windows`](../windows) for the original Windows implementation. The BLE/HCI packet-building logic (`emulator.py`) is identical between the two — only the low-level transport differs.

---

## ⚠️ Status

- Experimental and unstable
- Requires a Bluetooth controller exposed via BlueZ (`hciN`)
- Results may vary depending on Bluetooth chipset and driver support

---

## Technical Overview

Instead of replacing the OS driver (as required on Windows via Zadig/WinUSB), Linux exposes raw HCI access natively through BlueZ's **HCI user channel**. Opening a socket on `AF_BLUETOOTH` / `BTPROTO_HCI` with channel `HCI_CHANNEL_USER` hands the controller over for exclusive raw HCI command/event access, detaching it from `bluetoothd` and the kernel Bluetooth stack for as long as the socket is held open.

This means `blekeyboard` on Linux has **no external dependencies** — it talks to the adapter using only Python's standard `socket` module.

---

## Prerequisites & Installation

### 1. Hardware Compatibility

Requires a Bluetooth Low Energy (BLE 4.2+) controller recognized by BlueZ (visible via `hciconfig` / `bluetoothctl` as `hci0`, `hci1`, etc.).

### 2. Bring the adapter down

⚠️ **This step is required for the library to function correctly.**

The HCI user channel requires the target adapter to be down before it can be claimed:

```bash
sudo hciconfig hci0 down
```

> This will temporarily disable normal Bluetooth functionality (mouse, headphones, etc.) on that adapter until it's brought back up.

### 3. Permissions

Opening a raw HCI user-channel socket requires `CAP_NET_ADMIN`. Simplest option is running as root:

```bash
sudo python3 -m blekeyboard
```

Alternatively, grant the capability to your Python interpreter instead of running fully as root:

```bash
sudo setcap cap_net_admin+eip $(readlink -f $(which python3))
```

### 4. Package Installation

Install locally:

```bash
pip install -e .
```

## Usage

### CLI Execution

Run the BLE keyboard service (as root, or with `CAP_NET_ADMIN` granted):

```bash
sudo python -m blekeyboard
```

### Programmatic API

```python
import time
from blekeyboard.hijack import HCITransport
from blekeyboard.emulator import BLEBroadcaster

# Initialize the raw HCI transport layer against hci0
transport = HCITransport(dev_id=0)
broadcaster = BLEBroadcaster(transport)

try:
    # Claim the adapter's HCI user channel
    transport.connect()
    broadcaster.configure_advertising(interval_ms=400)

    # Define the advertised device namespace
    broadcaster.set_advertising_payload("BLE-Ducky")

    # Fire up the transmitter
    broadcaster.set_state(enable=True)
    print("[INFO] Peripheral advertising sequence live.")

    # Maintain active link state to prevent firmware watchdog sleep
    while True:
        time.sleep(10)
        broadcaster.send_keepalive_ping()

finally:
    # Graceful hardware release sequence
    broadcaster.set_state(enable=False)
    transport.release()
```

## Environment Recovery (Restoring Normal Bluetooth)

Closing the transport (`transport.release()`) releases the user channel automatically. To fully hand the adapter back to BlueZ:

```bash
sudo hciconfig hci0 up
```

Normal desktop Bluetooth functionality should resume immediately — no reboot required.

## Disclaimer

This project is intended for educational and **experimental (for now)** use only.

BLE keyboard behavior is highly dependent on hardware and driver support, and may not function consistently across all devices or operating system configurations.
