import sys
import time
from blekeyboard.hijack import USBTransport
from blekeyboard.emulator import BLEBroadcaster

def main():
    print("Starting blekeyboard emulator service...")
    
    # Target hardware device context: Realtek Combo Card (VID 0x13D3, PID 0x3529)
    transport = USBTransport(vendor_id=0x13D3, product_id=0x3529)
    broadcaster = BLEBroadcaster(transport)
    
    try:
        transport.connect()
        
        # Configure initial link parameters before enabling transmission state
        broadcaster.configure_advertising(interval_ms=400)
        time.sleep(0.1)
        
        broadcaster.set_advertising_payload("BLE-Ducky")
        time.sleep(0.1)
        
        # Initialize TX power register to a safe median baseline (0 dBm)
        current_power = 0  
        broadcaster.set_tx_power(current_power)
        time.sleep(0.1)
        
        broadcaster.set_state(enable=True)
        print("BLE advertising enabled with automatic power leveling.")
        print("Press Ctrl+C to stop.")
        
        last_keepalive_time = time.time()
        
        # Power leveling algorithmic constants
        TARGET_RSSI = -70
        DEADZONE = 5
        MIN_POWER_LIMIT = -20
        MAX_POWER_LIMIT = 8   
        
        while True:
            current_rssi = transport.get_last_rssi() 
            
            # Execute conditional switch: Check if connection is active and stable
            if current_rssi == -127 or current_rssi <= -90:
                # Disconnected or idle state: Force energy-efficient advertising baseline
                if current_power != 0:
                    current_power = 0
                    broadcaster.set_tx_power(current_power)
            else:
                # Active connection state: Safely process proportional corrections
                error = TARGET_RSSI - current_rssi
                
                if error > DEADZONE:
                    current_power = max(MIN_POWER_LIMIT, min(current_power + 2, MAX_POWER_LIMIT))
                    print(f"[Power Leveling] Signal weak ({current_rssi} dBm). Scaling UP to {current_power} dBm")
                    broadcaster.set_tx_power(current_power)
                    
                elif error < -DEADZONE:
                    current_power = max(MIN_POWER_LIMIT, min(current_power - 2, MAX_POWER_LIMIT))
                    print(f"[Power Leveling] Signal strong ({current_rssi} dBm). Scaling DOWN to {current_power} dBm")
                    broadcaster.set_tx_power(current_power)

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
    finally:
        broadcaster.set_state(enable=False)
        transport.release()
        print("Hardware interfaces released.")
        sys.exit(0)

if __name__ == "__main__":
    main()