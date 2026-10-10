# blekeyboard (alpha)

`blekeyboard` is a Python package that allows you to emulate a wireless keyboard using Bluetooth Low Energy (BLE). It is inspired by the popular ESP32 library **ESP32-BLE-Keyboard** by T-vK, and aims to bring similar BLE HID keyboard functionality to Windows systems using native Bluetooth hardware.

By leveraging the system’s Bluetooth controller in a compatible mode, `blekeyboard` enables Python-based BLE keyboard emulation without requiring external hardware such as an ESP32 or USB HID injection devices.

---

## ⚠️ Status

- Tested only on **Windows 10**
- Functionality is **experimental and unstable**
- Results may vary depending on Bluetooth chipset and driver support
- Some systems may not support BLE peripheral/HID emulation properly

---

## Technical Overview

Modern desktop operating systems typically restrict applications from acting as BLE peripheral devices or exposing low-level Bluetooth HID capabilities directly.

`blekeyboard` works by using a generic USB driver layer to access the Bluetooth adapter in a mode that allows direct communication with the controller. This enables BLE advertising configuration, connection handling, and HID keyboard emulation from Python.

> Note: BLE peripheral support is hardware and driver dependent, and may not be available on all systems.

---

## Prerequisites & Installation

### 1. Hardware Compatibility

Requires a Bluetooth Low Energy (BLE 4.2+) controller.

This package is primarily tested on:

- Realtek (RTL88xx) Bluetooth adapters  
- Intel (AX2xx) Bluetooth adapters  

These represent most modern laptop Bluetooth chipsets.

---

### 2. Low-Level Hardware Mapping (Windows Setup)

⚠️ **This step is required for the library to function correctly.**

You must replace the default Windows Bluetooth driver with a generic USB driver using Zadig.

> This will temporarily disable normal Bluetooth functionality (mouse, headphones, etc.) until reverted.

#### Steps:

1. Download **Zadig**: https://zadig.akeo.ie/
2. Open Zadig and enable:
   - `Options → List All Devices`
3. Select your **Bluetooth adapter** (e.g., Realtek Bluetooth Adapter)
4. Verify device IDs (example: `13D3:3529`)
5. Select driver:
   - **WinUSB**
6. Click **Replace Driver**
7. Reboot your system

---

### 3. Package Installation

Install locally:

```powershell
pip install -e .
```
Ensure `libusb-1.0.dll` is available in your working directory to support USB communication in restricted environments.

### Note
`libusb-1.0.dll` is x64, further updates to this package will expand to different system architectures.

## Usage
### CLI Execution

Run the BLE keyboard service:
```powershell
python -m blekeyboard
```

### Programmatic API

```python
import time
from blekeyboard.hijack import USBTransport
from blekeyboard.emulator import BLEBroadcaster

# Initialize the raw USB transport layer
transport = USBTransport(vendor_id=0x13D3, product_id=0x3529) # Note: Remember to swap out the vendor and product id to the ones that match with zadig
broadcaster = BLEBroadcaster(transport)

try:
    # Bind hardware and initialize low-level controller
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

To hand hardware control back to the Windows OS kernel and re-enable normal desktop Bluetooth:

1. Open **Device Manager**.
2. Expand **Universal Serial Bus devices** all the way at the bottom.
3. Right-click your Bluetooth adapter.
4. Select **Update driver**.
5. Choose:
- Browse my computer for drivers
- Let me pick from a list of available drivers
6. Select the original vendor driver (e.g., Realtek Bluetooth Adapter).
7. Reboot your system
8. Windows should spin up your normal desktop Bluetooth functionality again.

## Disclaimer

This project is intended for educational and **experimental (for now)** use only.

BLE keyboard behavior is highly dependent on hardware and driver support, and may not function consistently across all devices or operating system configurations.