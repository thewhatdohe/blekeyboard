# blekeyboard (Windows)

Windows implementation of `blekeyboard`, using a generic WinUSB driver and `libusb` to obtain raw access to a local Bluetooth controller.

See [`../linux`](../linux) for the Linux implementation. The HCI packet construction layer (`emulator.py`) is common to both platforms; only the transport layer (`hijack.py`) differs.

## Project status

Alpha. Advertising is implemented: the controller is claimed, reset, configured, and broadcasts a discoverable device name. The GATT, pairing, and HID layers are in development, so a connecting device will find no services and cannot receive keystrokes. See the [project roadmap](../README.md#roadmap).

Tested on Windows 10.

## How it works

Windows does not permit applications to act as BLE peripherals or to reach the controller's HID capabilities directly. Replacing the vendor driver with a generic USB driver exposes the adapter's HCI endpoints, allowing BLE configuration to be driven from Python.

Peripheral support is dependent on hardware and driver capability and is not available on all systems.

## Requirements

- Python 3.10 or later
- A Bluetooth Low Energy 4.2 or later controller

Primarily tested against Realtek (RTL88xx) and Intel (AX2xx) adapters, which cover most modern laptop chipsets.

## Installation

### 1. Replace the adapter driver

The library cannot reach the controller until the vendor driver is replaced with WinUSB. This suspends normal Bluetooth functionality, including connected peripherals such as mice and headsets, until the original driver is restored.

1. Download [Zadig](https://zadig.akeo.ie/).
2. Enable **Options → List All Devices**.
3. Select the Bluetooth adapter, for example *Realtek Bluetooth Adapter*.
4. Confirm the device identifiers, for example `13D3:3529`.
5. Select the **WinUSB** driver.
6. Select **Replace Driver**.
7. Reboot.

### 2. Install the package

```powershell
pip install -e .
```

`libusb-1.0.dll` must be present in the working directory to support USB communication in restricted environments. The bundled binary is x64; additional architectures are planned.

## Usage

### Command line

```powershell
python -m blekeyboard
```

Starts the advertising service and holds the adapter until interrupted with `Ctrl+C`.

### Library

```python
import time

from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.hijack import USBTransport

# Replace the identifiers with those shown for the adapter in Zadig.
transport = USBTransport(vendor_id=0x13D3, product_id=0x3529)
broadcaster = BLEBroadcaster(transport)

try:
    # Claim the USB interface and bind to the controller.
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
| `USBTransport.connect()` | Locates the adapter and claims interface 0. |
| `USBTransport.send_control_packet(packet)` | Writes an HCI command packet to the controller. |
| `USBTransport.read_event_packet(timeout_ms)` | Reads an HCI event packet, returning an empty list on timeout. |
| `USBTransport.release()` | Releases the interface and closes the session. |
| `BLEBroadcaster.reset_controller()` | Issues HCI Reset. Required after claiming the adapter. |
| `BLEBroadcaster.configure_advertising(interval_ms)` | Sets advertising parameters. Accepts 20 ms to 10240 ms. |
| `BLEBroadcaster.set_advertising_payload(name)` | Sets advertising data to flags and the complete local name, up to 26 bytes. |
| `BLEBroadcaster.set_state(enable)` | Enables or disables advertising. |
| `BLEBroadcaster.send_keepalive_ping()` | Reads local version information as a controller liveness check. |

## Restoring normal Bluetooth operation

To return control of the adapter to Windows:

1. Open **Device Manager**.
2. Expand **Universal Serial Bus devices**.
3. Right-click the Bluetooth adapter and select **Update driver**.
4. Select **Browse my computer for drivers**, then **Let me pick from a list of available drivers**.
5. Select the original vendor driver, for example *Realtek Bluetooth Adapter*.
6. Reboot.

Normal desktop Bluetooth functionality resumes after restart.

## Testing

```powershell
pip install -e ".[dev]"
pytest
```

## Disclaimer

This project is intended for educational and experimental use. Behaviour depends heavily on controller and driver support and may vary across hardware and operating system configurations.
