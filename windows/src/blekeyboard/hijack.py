import os
import sys
import usb.core
import usb.util
import usb.backend.libusb1
import warnings

class USBTransport:
    """
    Manages raw USB transport and interface allocation.
    """
    
    def __init__(self, vendor_id: int = 0x13D3, product_id: int = 0x3529):
        self.vendor_id = vendor_id
        self.product_id = product_id
        self._last_rssi = -127 # Lowest strength possible (basically off)
        self.device = None
        self._backend = self._resolve_backend()

    def _resolve_backend(self):
        """Resolves the libusb backend, preferring a local binary."""
        project_root = os.getcwd()
        dll_path = os.path.join(project_root, "libusb-1.0.dll")
        if os.path.exists(dll_path):
            return usb.backend.libusb1.get_backend(find_library=lambda x: dll_path)
        
        warnings.warn("Local libusb-1.0.dll not found. Relying on system environment.", ImportWarning)
        return None

    def connect(self):
        """Locates the USB device and claims interface 0."""
        self.device = usb.core.find(
            idVendor=self.vendor_id, 
            idProduct=self.product_id, 
            backend=self._backend
        )
        
        if self.device is None:
            raise RuntimeError(f"USB device {self.vendor_id:04x}:{self.product_id:04x} not found.")
            
        try:
            usb.util.claim_interface(self.device, 0)
        except usb.core.USBError as e:
            raise RuntimeError(f"Failed to claim interface 0. Check driver configuration. ({e})")
        
    def get_last_rssi(self) -> int:
        """Returns the most recently captured raw RSSI value."""
        return self._last_rssi

    def send_control_packet(self, packet: list[int]):
        """Executes a synchronous USB control transfer to endpoint 0."""
        if not self.device:
            raise RuntimeError("Cannot transmit: transport session is not established.")
        self.device.ctrl_transfer(
            bmRequestType=0x20,
            bRequest=0x00,
            wValue=0,
            wIndex=0,
            data_or_wLength=packet
        )
    
    def read_event_packet(self, timeout_ms: int = 1000) -> list[int]:
        """Reads raw bytes from the Bluetooth controller event endpoint."""
        if not self.device:
            raise RuntimeError("Cannot receive: transport session is not established.")
        try:
            # 0x81 is the standard HCI Event interrupt endpoint
            # 64 bytes is the standard maximum packet size for this endpoint
            raw_data = self.device.read(0x81, 64, timeout=timeout_ms)
            return list(raw_data)
        except usb.core.USBError as e:
            # USB timeout (error code 11 or 'timed out') is normal when no data is ready
            if e.errno == 11 or "timed out" in str(e).lower():
                return []
            raise e


    def release(self):
        """Releases the active interface and closes the session."""
        if self.device:
            try:
                usb.util.release_interface(self.device, 0)
            except usb.core.USBError:
                pass