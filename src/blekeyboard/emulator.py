import time
from typing import List
from blekeyboard.hijack import USBTransport

class BLEBroadcaster:
    """
    Constructs Bluetooth Host Controller Interface (HCI) commands.
    """
    
    OGF_LE_CONTROLLER = 0x08
    OGF_INFORMATIONAL = 0x04

    def __init__(self, transport: USBTransport):
        self.transport = transport

    def _build_hci_packet(self, ocf: int, ogf: int, data: List[int] = None) -> List[int]:
        """Assembles an HCI command packet header."""
        data = data or []
        opcode = (ogf << 10) | ocf
        header = [opcode & 0xFF, (opcode >> 8) & 0xFF, len(data)]
        return header + data

    def configure_advertising(self, interval_ms: int = 800):
        """Initializes standard ADV_IND Link Layer parameters."""
        slots = int(interval_ms / 0.625)
        slots_low = slots & 0xFF
        slots_high = (slots >> 8) & 0xFF
        
        params = [
            slots_low, slots_high,
            slots_low, slots_high,
            0x00,
            0x00,
            0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07,
            0x00
        ]
        packet = self._build_hci_packet(ocf=0x0006, ogf=self.OGF_LE_CONTROLLER, data=params)
        self.transport.send_control_packet(packet)

    def set_advertising_payload(self, name: str):
        """Constructs an Extended Inquiry Response advertising payload."""
        name_bytes = name.encode('utf-8')
        if len(name_bytes) > 26:
            raise ValueError("Device name string exceeds standard advertising slot bounds (max 26 bytes).")
            
        flags = [0x02, 0x01, 0x06]
        name_header = [len(name_bytes) + 1, 0x09]
        
        payload_data = flags + name_header + list(name_bytes)
        total_len = len(payload_data)
        
        full_packet_args = [total_len] + payload_data + ([0x00] * (31 - total_len))
        packet = self._build_hci_packet(ocf=0x0008, ogf=self.OGF_LE_CONTROLLER, data=full_packet_args)
        self.transport.send_control_packet(packet)

    def set_state(self, enable: bool):
        """Toggles the controller's radio transmission state."""
        state_byte = [0x01 if enable else 0x00]
        packet = self._build_hci_packet(ocf=0x000A, ogf=self.OGF_LE_CONTROLLER, data=state_byte)
        self.transport.send_control_packet(packet)

    def send_keepalive_ping(self):
        """Dispatches an informational query to maintain active firmware state."""
        packet = self._build_hci_packet(ocf=0x0001, ogf=self.OGF_INFORMATIONAL, data=[])
        self.transport.send_control_packet(packet)