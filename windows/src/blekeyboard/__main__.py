import sys
import time
from blekeyboard.hijack import USBTransport
from blekeyboard.emulator import BLEBroadcaster

def main():
    print("Starting blekeyboard emulator service...")

    # Target hardware device context: Realtek Combo Card (VID 0x13D3, PID 0x3529)
    transport = USBTransport(vendor_id=0x13D3, product_id=0x3529)
    broadcaster = BLEBroadcaster(transport)
    exit_code = 0

    try:
        transport.connect()

        # A freshly claimed controller is uninitialized, so reset it before configuring.
        broadcaster.reset_controller()
        time.sleep(0.1)

        # Configure initial link parameters before enabling transmission state
        broadcaster.configure_advertising(interval_ms=400)
        time.sleep(0.1)

        broadcaster.set_advertising_payload("BLE-Ducky")
        time.sleep(0.1)

        broadcaster.set_state(enable=True)
        print("BLE advertising enabled.")
        print("Press Ctrl+C to stop.")

        last_keepalive_time = time.time()

        while True:
            # Drain controller events so the endpoint buffer does not fill up.
            transport.read_event_packet(timeout_ms=200)

            # Prevent transport-layer host watchdog termination (10-second window)
            if time.time() - last_keepalive_time >= 10.0:
                broadcaster.send_keepalive_ping()
                last_keepalive_time = time.time()

            # Polling resolution interval for the control loop
            time.sleep(0.5)

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

if __name__ == "__main__":
    sys.exit(main())
