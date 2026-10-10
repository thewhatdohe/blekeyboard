import sys
import time
from blekeyboard.hijack import USBTransport
from blekeyboard.emulator import BLEBroadcaster

def main():
    print("Starting blekeyboard emulator service...")
    
    transport = USBTransport(vendor_id=0x13D3, product_id=0x3529)
    broadcaster = BLEBroadcaster(transport)
    
    try:
        transport.connect()
        
        broadcaster.configure_advertising(interval_ms=400)
        time.sleep(0.1)
        
        broadcaster.set_advertising_payload("BLE-Ducky")
        time.sleep(0.1)
        
        broadcaster.set_state(enable=True)
        print("BLE advertising enabled.")
        print("Press Ctrl+C to stop.")
        
        # Dispatch periodic informational queries to prevent hardware watchdog timeouts
        while True:
            time.sleep(10)
            broadcaster.send_keepalive_ping()
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"\nFatal error: {e}")
    finally:
        broadcaster.set_state(enable=False)
        transport.release()
        print("Hardware interfaces released.")
        sys.exit(0)

if __name__ == "__main__":
    main()