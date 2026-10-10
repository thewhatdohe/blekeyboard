import time
from typing import List
from blekeyboard.hijack import USBTransport

class BLEBroadcaster:
    """
    Constructs Bluetooth Host Controller Interface (HCI) commands.
    """
    
    # OGF stands for Opcode Group Field. It categorizes what part of the Bluetooth chip we want to talk to.
    # 0x08 tells the chip we are sending Bluetooth Low Energy (LE) specific commands.
    OGF_LE_CONTROLLER = 0x08
    
    # 0x04 tells the chip we are asking for informational data (like firmware versions or MAC addresses).
    OGF_INFORMATIONAL = 0x04

    def __init__(self, transport: USBTransport):
        self.transport = transport

    def _build_hci_packet(self, ocf: int, ogf: int, data: List[int] = None) -> List[int]:
        """Assembles an HCI command packet header."""
        data = data or []
        
        # OCF stands for Opcode Command Field (the specific action we want the chip to take).
        # The Bluetooth spec requires combining the OGF and OCF into a single 16-bit Opcode number.
        # We shift the OGF 10 bits to the left and merge it with the OCF using a bitwise OR (|).
        opcode = (ogf << 10) | ocf
        
        # Bluetooth chips expect data in "Little-Endian" format (lowest byte first).
        # opcode & 0xFF extracts the bottom 8 bits (low byte).
        # (opcode >> 8) & 0xFF extracts the top 8 bits (high byte).
        # len(data) tells the chip exactly how many parameter bytes are following this header.
        header = [opcode & 0xFF, (opcode >> 8) & 0xFF, len(data)]
        
        # Merge the 3-byte header with our actual payload data array and return it.
        return header + data

    def configure_advertising(self, interval_ms: int = 800):
        """Initializes standard ADV_IND Link Layer parameters."""
        # BLE radio timing is measured in "slots" of 0.625 milliseconds.
        # Dividing our milliseconds by 0.625 converts it into the slot count the chip understands.
        slots = int(interval_ms / 0.625)
        
        # The slot count is often too big for a single byte (max 255).
        # So we split the 16-bit slot integer into two 8-bit bytes (low byte and high byte).
        slots_low = slots & 0xFF
        slots_high = (slots >> 8) & 0xFF
        
        # This list forms the exact structure required by the "LE Set Advertising Parameters" command.
        params = [
            slots_low, slots_high,  # Minimum Advertising Interval (how fast it can broadcast)
            slots_low, slots_high,  # Maximum Advertising Interval (how slow it can broadcast)
            0x00,                   # Advertising Type: 0x00 = ADV_IND (Connectable and visible to everyone)
            0x00,                   # Own Address Type: 0x00 = Use the chip's permanent, public MAC address
            0x00,                   # Peer Address Type: 0x00 = Public address (used if targeting a specific device)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Peer MAC Address: All 0x00 means "don't target anyone, broadcast to all"
            0x07,                   # Channel Map: 0x07 (binary 00000111) tells it to use BLE channels 37, 38, and 39
            0x00                    # Filter Policy: 0x00 = Allow scan and connection requests from any device
        ]
        
        # OCF 0x0006 is the official Bluetooth spec code for "LE Set Advertising Parameters".
        packet = self._build_hci_packet(ocf=0x0006, ogf=self.OGF_LE_CONTROLLER, data=params)
        self.transport.send_control_packet(packet)

    def set_advertising_payload(self, name: str):
        """Constructs an Extended Inquiry Response advertising payload."""
        # Convert our string name (e.g., "blekeyboard") into raw numerical bytes.
        name_bytes = name.encode('utf-8')
        
        # A standard single BLE advertising packet can only hold 31 bytes total.
        # We use 5 bytes for headers/flags, leaving exactly 26 bytes maximum for the device name.
        if len(name_bytes) > 26:
            raise ValueError("Device name string exceeds standard advertising slot bounds (max 26 bytes).")
            
        # Flags tell smartphones what kind of device this is.
        # 0x02 = Length of flag data (2 bytes). 0x01 = Type (Flags). 0x06 = General Discoverable & BR/EDR Not Supported.
        flags = [0x02, 0x01, 0x06]
        
        # The name section needs its own mini-header inside the packet.
        # len(name_bytes) + 1 tells the phone how long the name data block is (including the type byte).
        # 0x09 is the DataType flag meaning "Complete Local Name".
        name_header = [len(name_bytes) + 1, 0x09]
        
        # Combine the flags, the name header, and the actual characters of the name into one payload.
        payload_data = flags + name_header + list(name_bytes)
        total_len = len(payload_data)
        
        # The BLE chip requires the payload argument to be exactly 32 bytes long.
        # Byte 0 must be the length of our actual data. 
        # The remaining space up to 31 bytes must be padded out with empty zeroes (0x00).
        full_packet_args = [total_len] + payload_data + ([0x00] * (31 - total_len))
        
        # OCF 0x0008 is the official Bluetooth spec code for "LE Set Advertising Data".
        packet = self._build_hci_packet(ocf=0x0008, ogf=self.OGF_LE_CONTROLLER, data=full_packet_args)
        self.transport.send_control_packet(packet)

    def set_state(self, enable: bool):
        """Toggles the controller's radio transmission state."""
        # Convert the true/false boolean into a 1 or a 0 byte for the hardware firmware.
        state_byte = [0x01 if enable else 0x00]
        
        # OCF 0x000A is the official Bluetooth spec code for "LE Set Advertise Enable".
        packet = self._build_hci_packet(ocf=0x000A, ogf=self.OGF_LE_CONTROLLER, data=state_byte)
        self.transport.send_control_packet(packet)

    def send_keepalive_ping(self):
        """Dispatches an informational query to maintain active firmware state."""
        # OCF 0x0001 under the Informational OGF reads the local version information from the chip.
        # This acts as a ping to make sure the controller didn't freeze or fall asleep.
        packet = self._build_hci_packet(ocf=0x0001, ogf=self.OGF_INFORMATIONAL, data=[])
        self.transport.send_control_packet(packet)
