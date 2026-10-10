# blekeyboard (alpha)

`blekeyboard` is a Python package that allows you to emulate a wireless keyboard using Bluetooth Low Energy (BLE), by talking raw HCI commands directly to a local Bluetooth controller. It is inspired by the popular ESP32 library **ESP32-BLE-Keyboard** by T-vK.

This repository is split by platform, since each requires a different low-level transport to get raw HCI access to the Bluetooth controller:

- [`windows/`](windows) — the original implementation. Uses Zadig/WinUSB + `libusb` to bypass the Windows Bluetooth stack. Tested on Windows 10.
- [`linux/`](linux) — a native port. Uses BlueZ's HCI user channel (`AF_BLUETOOTH` raw sockets) — no external drivers or dependencies required.

The core BLE/HCI packet-building logic (`emulator.py`, the `BLEBroadcaster` class) is identical across both — only the transport layer (`hijack.py`) differs. See each platform folder's README for setup and usage instructions.

## Disclaimer

This project is intended for educational and **experimental (for now)** use only.

BLE keyboard behavior is highly dependent on hardware and driver support, and may not function consistently across all devices or operating system configurations.
