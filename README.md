# blekeyboard

A Python library for driving a local Bluetooth controller directly through raw HCI commands to emulate a Bluetooth Low Energy (BLE) HID keyboard, without external hardware such as an ESP32 or a USB HID injection device.

Intended for authorized penetration testing and red team engagements, as a scriptable keystroke-injection tool for testers who lack access to purpose-built hardware. Inspired by the ESP32 library [ESP32-BLE-Keyboard](https://github.com/T-vK/ESP32-BLE-Keyboard) by T-vK.

## Project status

Alpha. On Linux, the full stack — advertising, connection handling, pairing, GATT/HID over GATT services, and key report delivery — is implemented and verified against real hardware: a phone paired through its own Bluetooth settings, enrolled the device as a keyboard, and received correctly encoded keystrokes over an encrypted link. Windows has the advertising layer only; see [Roadmap](#roadmap).

| Capability | Windows | Linux |
| --- | --- | --- |
| Raw HCI transport | Supported | Supported |
| Controller reset and configuration | Supported | Supported |
| Connectable advertising | Supported | Supported |
| Connection lifecycle events | Planned | Supported |
| L2CAP data transport | Planned | Supported |
| GATT server | Planned | Supported |
| Pairing and link encryption | Planned | Supported |
| HID over GATT services | Planned | Supported |
| Key report delivery | Planned | Supported |
| Scripting API (`Keyboard`) | Planned | Supported |
| Payload script runner | Planned | Planned |
| Persistent bonding | Planned | Planned |

Pairing uses the Just Works association model, the only one available to a device with no display and no keypad. It protects an established session from passive eavesdropping but not from an attacker present during pairing itself. Keys are not retained, so each connection pairs afresh.

### A real limitation of BLE injection

Unlike a wired USB "BadUSB" device, which is auto-enumerated the instant it is plugged in, BLE HID has no equivalent. The target's operating system will always prompt to confirm pairing with a new device before accepting input from it — even with no PIN involved, that confirmation is a platform-level gate this tool cannot bypass. This makes `blekeyboard` suited to engagements involving physical access and a plausible pretext for pairing a new peripheral, not silent drive-by injection.

## Roadmap

HID over GATT requires a host-side protocol stack above the HCI layer:

- [x] Connection lifecycle handling (HCI event mask, connection and disconnection events)
- [x] ACL data transport with L2CAP fragmentation and reassembly
- [x] ATT protocol and a GATT attribute server
- [x] Security Manager pairing and link encryption, which HID hosts require before accepting input
- [x] HID over GATT Profile services and report descriptors
- [x] Key report transmission and a `Keyboard` scripting API
- [ ] A payload script runner for semicolon-delimited command strings

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

This project is intended for authorized security testing and research. Use it only against systems you own or have explicit written permission to test; unauthorized access to computer systems is illegal in most jurisdictions. Behaviour depends heavily on controller and driver support and may vary across hardware and operating system configurations.

## License

Released under the MIT License. See [LICENSE](LICENSE).
