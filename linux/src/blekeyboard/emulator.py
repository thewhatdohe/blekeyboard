from typing import List
from blekeyboard.hijack import HCITransport

class BLEBroadcaster:
    """
    Constructs Bluetooth Host Controller Interface (HCI) commands.
    """

    # OGF stands for Opcode Group Field. It categorizes what part of the Bluetooth chip we want to talk to.
    # 0x08 tells the chip we are sending Bluetooth Low Energy (LE) specific commands.
    OGF_LE_CONTROLLER = 0x08

    # 0x04 tells the chip we are asking for informational data (like firmware versions or MAC addresses).
    OGF_INFORMATIONAL = 0x04

    # 0x03 covers controller and baseband control, such as resetting the chip.
    OGF_CONTROLLER_BASEBAND = 0x03

    # The controller's power-on event mask, which the spec defines as
    # 0x00001FFFFFFFFFFF. Notably it leaves LE Meta Event (bit 61) disabled,
    # so LE connection events are not delivered until we enable it.
    _DEFAULT_EVENT_MASK = 0x00001FFFFFFFFFFF
    _LE_META_EVENT_BIT = 1 << 61

    # The controller's default LE event mask already enables connection
    # complete, connection update complete and long term key request.
    # Bits 0-4 cover Connection Complete through Long Term Key Request; bits
    # 7 and 8 add Read Local P-256 Public Key Complete and Generate DHKey
    # Complete. Those last two are essential: without them the controller
    # still runs the LE Secure Connections key commands, but silently drops
    # their completion events, so pairing would hang waiting for a result
    # the controller was told not to report.
    _DEFAULT_LE_EVENT_MASK = 0x000000000000019F

    @staticmethod
    def _to_little_endian(value: int, width: int) -> List[int]:
        """Splits an integer into `width` bytes, lowest byte first."""
        return [(value >> (8 * i)) & 0xFF for i in range(width)]

    def __init__(self, transport: HCITransport):
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

    def reset_controller(self):
        """Resets the controller to a known state."""
        # A freshly claimed controller is uninitialized, so the spec expects an
        # HCI Reset before any other command. OCF 0x0003 under the Controller &
        # Baseband OGF is "Reset".
        packet = self._build_hci_packet(ocf=0x0003, ogf=self.OGF_CONTROLLER_BASEBAND, data=[])
        self.transport.send_control_packet(packet)

    def set_event_mask(self):
        """Enables delivery of LE Meta events alongside the controller defaults."""
        # Without this the controller withholds every LE Meta event, so a peer
        # could connect and the host would never be told.
        mask = self._DEFAULT_EVENT_MASK | self._LE_META_EVENT_BIT
        packet = self._build_hci_packet(
            ocf=0x0001,
            ogf=self.OGF_CONTROLLER_BASEBAND,
            data=self._to_little_endian(mask, 8),
        )
        self.transport.send_control_packet(packet)

    def set_le_event_mask(self):
        """Selects which LE Meta subevents the controller reports."""
        # Set explicitly rather than relying on the reset default, so the
        # subevents the stack depends on are stated in one place.
        packet = self._build_hci_packet(
            ocf=0x0001,
            ogf=self.OGF_LE_CONTROLLER,
            data=self._to_little_endian(self._DEFAULT_LE_EVENT_MASK, 8),
        )
        self.transport.send_control_packet(packet)

    def le_encrypt(self, key: bytes, plaintext: bytes):
        """
        Runs one AES-128 block through the controller's encryption engine.

        The Security Manager is built on AES-128, and borrowing the
        controller's engine keeps the package free of a crypto dependency.
        OCF 0x0017 under the LE group.
        """
        if len(key) != 16:
            raise ValueError(f"Key must be 16 bytes, got {len(key)}.")
        if len(plaintext) != 16:
            raise ValueError(f"Plaintext must be 16 bytes, got {len(plaintext)}.")

        packet = self._build_hci_packet(
            ocf=0x0017,
            ogf=self.OGF_LE_CONTROLLER,
            data=list(key) + list(plaintext),
        )
        self.transport.send_control_packet(packet)

    def le_rand(self):
        """Requests eight random octets from the controller. OCF 0x0018."""
        packet = self._build_hci_packet(ocf=0x0018, ogf=self.OGF_LE_CONTROLLER, data=[])
        self.transport.send_control_packet(packet)

    def le_read_local_p256_public_key(self):
        """
        Asks the controller to generate a fresh ECDH P-256 key pair and
        report the public half.

        Unlike LE Encrypt/LE Rand, the result does not arrive via Command
        Complete: this returns Command Status immediately, and the actual
        64-octet public key (X then Y, each least significant octet first)
        arrives later as an LE Meta subevent. OCF 0x0025.
        """
        packet = self._build_hci_packet(ocf=0x0025, ogf=self.OGF_LE_CONTROLLER, data=[])
        self.transport.send_control_packet(packet)

    def le_generate_dhkey(self, remote_public_key: bytes):
        """
        Starts computing the Diffie-Hellman shared secret from the peer's
        public key and the private key generated by the most recent
        le_read_local_p256_public_key() call.

        Like the public key request, the 32-octet DHKey arrives later via an
        LE Meta subevent, not Command Complete. OCF 0x0026.
        """
        if len(remote_public_key) != 64:
            raise ValueError(f"Remote public key must be 64 bytes, got {len(remote_public_key)}.")

        packet = self._build_hci_packet(
            ocf=0x0026, ogf=self.OGF_LE_CONTROLLER, data=list(remote_public_key))
        self.transport.send_control_packet(packet)

    def read_bd_addr(self):
        """Reads the controller's own public address. OCF 0x0009, informational group."""
        packet = self._build_hci_packet(ocf=0x0009, ogf=self.OGF_INFORMATIONAL, data=[])
        self.transport.send_control_packet(packet)

    def le_long_term_key_request_reply(self, handle: int, long_term_key: bytes):
        """
        Hands the controller the key for a link the peer is encrypting.

        The controller asks for this when the initiator starts encryption, and
        supplying it is what actually secures the link. OCF 0x001A.
        """
        if len(long_term_key) != 16:
            raise ValueError(f"Long term key must be 16 bytes, got {len(long_term_key)}.")

        packet = self._build_hci_packet(
            ocf=0x001A,
            ogf=self.OGF_LE_CONTROLLER,
            data=self._to_little_endian(handle, 2) + list(long_term_key),
        )
        self.transport.send_control_packet(packet)

    def le_long_term_key_request_negative_reply(self, handle: int):
        """Tells the controller no key is available, aborting encryption. OCF 0x001B."""
        packet = self._build_hci_packet(
            ocf=0x001B,
            ogf=self.OGF_LE_CONTROLLER,
            data=self._to_little_endian(handle, 2),
        )
        self.transport.send_control_packet(packet)

    def read_le_buffer_size(self):
        """Asks the controller how much outbound ACL data it can hold."""
        # The reply gives the maximum LE ACL payload and how many such packets
        # the controller can buffer, which together govern fragmentation and
        # flow control. OCF 0x0002 under the LE group.
        packet = self._build_hci_packet(ocf=0x0002, ogf=self.OGF_LE_CONTROLLER, data=[])
        self.transport.send_control_packet(packet)

    def configure_advertising(self, interval_ms: int = 800):
        """Initializes standard ADV_IND Link Layer parameters."""
        # BLE radio timing is measured in "slots" of 0.625 milliseconds.
        # Dividing our milliseconds by 0.625 converts it into the slot count the chip understands.
        slots = int(interval_ms / 0.625)

        # The spec only accepts slot counts from 0x0020 to 0x4000 (20ms to 10240ms).
        # Outside that range the controller rejects the command, so fail loudly here instead.
        if not 0x0020 <= slots <= 0x4000:
            raise ValueError(
                f"Advertising interval must be between 20ms and 10240ms (got {interval_ms}ms)."
            )

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

    def set_advertising_payload(self, name: str, service_uuids: List[int] = None):
        """
        Constructs the LE advertising data payload: flags, the complete local
        name, and optionally a list of 16-bit service UUIDs.

        Advertising the HID service UUID is what lets a host recognise and
        offer to pair the device as a keyboard before any connection is made,
        rather than showing it as an unidentified peripheral.
        """
        # Convert our string name (e.g., "blekeyboard") into raw numerical bytes.
        name_bytes = name.encode('utf-8')

        # Flags tell smartphones what kind of device this is.
        # 0x02 = Length of flag data (2 bytes). 0x01 = Type (Flags). 0x06 = General Discoverable & BR/EDR Not Supported.
        flags = [0x02, 0x01, 0x06]

        # The name section needs its own mini-header inside the packet.
        # len(name_bytes) + 1 tells the phone how long the name data block is (including the type byte).
        # 0x09 is the DataType flag meaning "Complete Local Name".
        name_header = [len(name_bytes) + 1, 0x09]

        # Combine the flags, the name header, and the actual characters of the name into one payload.
        payload_data = flags + name_header + list(name_bytes)

        if service_uuids:
            # Type 0x03 is the Complete List of 16-bit Service Class UUIDs,
            # each written little-endian as everywhere else in HCI.
            uuid_bytes = []
            for uuid in service_uuids:
                uuid_bytes += [uuid & 0xFF, (uuid >> 8) & 0xFF]
            payload_data += [len(uuid_bytes) + 1, 0x03] + uuid_bytes

        total_len = len(payload_data)

        # A single advertising packet can only hold 31 bytes total.
        if total_len > 31:
            raise ValueError(
                f"Advertising payload of {total_len} bytes exceeds the 31 byte limit; "
                "shorten the name or advertise fewer services."
            )

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
