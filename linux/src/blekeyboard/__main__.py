import sys
import time

from blekeyboard.emulator import BLEBroadcaster
from blekeyboard.hci import (
    ROLE_PERIPHERAL,
    ConnectionComplete,
    DisconnectionComplete,
    parse_event,
)
from blekeyboard.hijack import HCITransport

DEVICE_NAME = "BLE-Ducky"
KEEPALIVE_INTERVAL_SECONDS = 10.0


def main():
    print("Starting blekeyboard emulator service...")

    # Target hardware device context: local Bluetooth adapter hci0.
    transport = HCITransport(dev_id=0)
    broadcaster = BLEBroadcaster(transport)
    peers = {}
    exit_code = 0

    try:
        transport.connect()

        # A freshly claimed controller is uninitialized, so reset it before
        # configuring anything else.
        broadcaster.reset_controller()
        time.sleep(0.1)

        # The reset default masks off LE Meta events, so connection events
        # would never reach us without this.
        broadcaster.set_event_mask()
        broadcaster.set_le_event_mask()
        time.sleep(0.1)

        broadcaster.configure_advertising(interval_ms=400)
        time.sleep(0.1)

        broadcaster.set_advertising_payload(DEVICE_NAME)
        time.sleep(0.1)

        broadcaster.set_state(enable=True)
        print(f"Advertising as '{DEVICE_NAME}'.")
        print("Press Ctrl+C to stop.")

        last_keepalive = time.time()

        while True:
            # The read timeout paces the loop, so no additional sleep is needed.
            event = parse_event(transport.read_event_packet(timeout_ms=200))

            if isinstance(event, ConnectionComplete):
                _handle_connection(event, peers, broadcaster)
            elif isinstance(event, DisconnectionComplete):
                _handle_disconnection(event, peers, broadcaster)

            if time.time() - last_keepalive >= KEEPALIVE_INTERVAL_SECONDS:
                broadcaster.send_keepalive_ping()
                last_keepalive = time.time()

    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"\nFatal error: {e}")
        exit_code = 1
    finally:
        # The transport may never have been established, in which case there is
        # nothing to wind down and set_state would raise over the real error.
        try:
            broadcaster.set_state(enable=False)
        except RuntimeError:
            pass
        transport.release()
        print("Hardware interfaces released.")

    return exit_code


def _handle_connection(event, peers, broadcaster):
    """Records an established link, or restarts advertising if it failed."""
    if event.status != 0x00:
        print(f"Connection failed with status 0x{event.status:02X}.")
        broadcaster.set_state(enable=True)
        return

    peers[event.handle] = event.peer_address
    role = "peripheral" if event.role == ROLE_PERIPHERAL else "central"
    print(f"Connected to {event.peer_address} as {role}, handle 0x{event.handle:04X}.")


def _handle_disconnection(event, peers, broadcaster):
    """Drops the link and returns the controller to advertising."""
    peer = peers.pop(event.handle, "unknown peer")
    print(f"Disconnected from {peer}, reason 0x{event.reason:02X}.")

    # The controller stops advertising once a connection is established, so it
    # has to be re-enabled to become discoverable again.
    broadcaster.set_state(enable=True)
    print(f"Advertising as '{DEVICE_NAME}' again.")


if __name__ == "__main__":
    sys.exit(main())
