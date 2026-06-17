import os
import sys
import usb.core
import usb.util
import usb.backend.libusb1

class USBTransport:
    """Manages raw USB infrastructure, DLL path overrides, and interface claims."""
    
    def __init__(self, vendor_id: int = 0x13D3, product_id: int = 0x3529):
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.device = None
        self._backend = self._resolve_backend()

    def _resolve_backend(self):
        """Forces custom DLL loading for Python 3.14+ architectures."""
        project_root = os.getcwd()
        dll_path = os.path.join(project_root, "libusb-1.0.dll")
        if os.path.exists(dll_path):
            print(f"[DEBUG] Injecting local backend link: {dll_path}")
            return usb.backend.libusb1.get_backend(find_library=lambda x: dll_path)
        print("[WARN] Local libusb-1.0.dll missing. Falling back to default system search.")
        return None

    def connect(self):
        """Finds the device and exclusively claims interface 0."""
        print(f"[DEBUG] Scanning USB bus for [{hex(self.vendor_id)}:{hex(self.product_id)}]...")
        self.device = usb.core.find(
            idVendor=self.vendor_id, 
            idProduct=self.product_id, 
            backend=self._backend
        )
        
        if self.device is None:
            raise RuntimeError(f"Target USB hardware device {hex(self.vendor_id)}:{hex(self.product_id)} not found.")
            
        print("[SUCCESS] Hardware silicon detached from OS and mapped.")
        
        try:
            usb.util.claim_interface(self.device, 0)
            print("[SUCCESS] Interface 0 claimed exclusively. Host stack bypassed.")
        except usb.core.USBError as e:
            raise RuntimeError(f"Failed to claim interface. Verify WinUSB driver via Zadig. Details: {e}")

    def send_control_packet(self, packet: list[int]):
        """Transmits raw control transfer packet to endpoint 0."""
        if not self.device:
            raise RuntimeError("Cannot transmit data. No active transport session.")
        self.device.ctrl_transfer(
            bmRequestType=0x20,  # Class, Interface
            bRequest=0x00,       # HCI Command Request
            wValue=0,
            wIndex=0,
            data_or_wLength=packet
        )

    def release(self):
        """Cleans up kernel interfaces gracefully."""
        if self.device:
            try:
                usb.util.release_interface(self.device, 0)
                print("[INFO] USB hardware interface released cleanly.")
            except Exception:
                pass