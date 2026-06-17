import sys
import time
from blekeyboard.hijack import USBTransport
from blekeyboard.emulator import BLEBroadcaster

def main():
    print("=========================================")
    print("     RAW BLE HARDWARE BYPASS SERVICE     ")
    print("=========================================")
    
    transport = USBTransport(vendor_id=0x13D3, product_id=0x3529)
    broadcaster = BLEBroadcaster(transport)
    
    try:
        transport.connect()
        
        print("\n[INIT] Instantiating Low-Energy Layer...")
        broadcaster.configure_advertising(interval_ms=400)
        time.sleep(0.1)
        
        broadcaster.set_advertising_payload("BLE-Ducky")
        time.sleep(0.1)
        
        broadcaster.set_state(enable=True)
        print("[SUCCESS] Active beacon transmission pulsing on air.")
        print("[CONTROL] Core running. Press Ctrl+C to terminate session.")
        
        # Keepalive loop to prevent Realtek chip firmware sleep/watchdog lockup
        while True:
            time.sleep(10)
            broadcaster.send_keepalive_ping()
            
    except KeyboardInterrupt:
        print("\n[INFO] Termination signal intercepted.")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Runtime broken: {e}")
    finally:
        broadcaster.set_state(enable=False)
        transport.release()
        print("[STATUS] Stack exited cleanly. Radio returned to idle.")
        sys.exit(0)

if __name__ == "__main__":
    main()