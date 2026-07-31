# blekeyboard

A Python library for driving a local Bluetooth controller directly through raw HCI commands, targeting Bluetooth Low Energy (BLE) HID keyboard emulation without external hardware such as an ESP32 or a USB HID injection device.

Inspired by the ESP32 library [ESP32-BLE-Keyboard](https://github.com/T-vK/ESP32-BLE-Keyboard) by T-vK.

## Project status

Alpha. The BLE advertising layer is implemented and verified against real hardware. HID input support is in development; see [Roadmap](#roadmap).

| Capability | Windows | Linux |
| --- | --- | --- |
| Raw HCI transport | Supported | Supported |
| Controller reset and configuration | Supported | Supported |
| Connectable advertising | Supported | Supported |
| Connection lifecycle events | Planned | Supported |
| L2CAP data transport | Planned | Supported |
| GATT server | Planned | Planned |
| Pairing and bonding | Planned | Planned |
| HID keyboard input | Planned | Planned |

Linux development is currently ahead of Windows. A connecting device is accepted and its requests are received, but because the GATT and HID layers are not yet present it will find no services and cannot receive keystrokes.

## Roadmap

HID over GATT requires a host-side protocol stack above the HCI layer:

- [x] Connection lifecycle handling (HCI event mask, connection and disconnection events)
- [x] ACL data transport with L2CAP fragmentation and reassembly
- [ ] ATT protocol and a GATT attribute server
- [ ] Security Manager pairing and link encryption, which HID hosts require before accepting input
- [ ] HID over GATT Profile services and report descriptors
- [ ] Key report transmission

## Repository layout

The project is split by platform, as each requires a different transport to obtain raw HCI access to the controller:

| Directory | Transport | Notes |
| --- | --- | --- |
| [`windows/`](windows) | Zadig/WinUSB with `libusb` | Bypasses the Windows Bluetooth stack. Tested on Windows 10. |
| [`linux/`](linux) | BlueZ HCI user channel (`AF_BLUETOOTH` raw sockets) | No external drivers or runtime dependencies. |

The HCI packet construction layer (`emulator.py`, class `BLEBroadcaster`) is common to both platforms; only the transport layer (`hijack.py`) differs. Refer to each platform directory for setup and usage instructions.

## Requirements

- Python 3.10 or later
- A Bluetooth Low Energy 4.2 or later controller

## Disclaimer

This project is intended for educational and experimental use. Behaviour depends heavily on controller and driver support and may vary across hardware and operating system configurations.

## License

Released under the MIT License. See [LICENSE](LICENSE).
