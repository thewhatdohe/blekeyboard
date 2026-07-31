# blekeyboard (alpha)

`blekeyboard` is a Python package that talks raw HCI commands directly to a local Bluetooth controller, with the goal of emulating a wireless keyboard over Bluetooth Low Energy (BLE). It is inspired by the popular ESP32 library **ESP32-BLE-Keyboard** by T-vK.

## ⚠️ Status

What works today is the **advertising layer**: claiming the controller, resetting it, configuring advertising parameters, broadcasting a device name, and holding the link open with keepalives.

**HID is not implemented yet.** There is no GATT server, no HID service, no HID report descriptor, and no connection handling. A phone or laptop scanning nearby will see the advertised name and can attempt to connect, but it will not find any services and cannot receive keystrokes. Despite the project name, this is currently a BLE *advertiser*, not a BLE HID peripheral.

| | Windows | Linux |
| --- | --- | --- |
| Raw HCI transport | ✅ | ✅ |
| Advertising | ✅ | ✅ |
| HID keyboard | ❌ planned | ❌ planned |

## Platforms

This repository is split by platform, since each requires a different low-level transport to get raw HCI access to the Bluetooth controller:

- [`windows/`](windows) — the original implementation. Uses Zadig/WinUSB + `libusb` to bypass the Windows Bluetooth stack. Tested on Windows 10.
- [`linux/`](linux) — a native port. Uses BlueZ's HCI user channel (`AF_BLUETOOTH` raw sockets) — no external drivers or dependencies required. Advertising verified on real hardware.

The core BLE/HCI packet-building logic (`emulator.py`, the `BLEBroadcaster` class) is identical across both — only the transport layer (`hijack.py`) differs. See each platform folder's README for setup and usage instructions.

## Disclaimer

This project is intended for educational and **experimental (for now)** use only.

BLE behavior is highly dependent on hardware and driver support, and may not function consistently across all devices or operating system configurations.
