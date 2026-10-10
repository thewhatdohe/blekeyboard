"""
Decoding of HCI events received from the controller.

The transport hands back raw H4-framed packets. This module turns the event
packets into structured records so the layers above can react to connection
lifecycle changes without re-deriving byte offsets.
"""

from dataclasses import dataclass, field

# H4 UART framing packet type indicators used on raw HCI sockets.
HCI_COMMAND_PKT = 0x01
HCI_ACLDATA_PKT = 0x02
HCI_EVENT_PKT = 0x04

# Event codes carried in byte 1 of an event packet.
EVT_DISCONNECTION_COMPLETE = 0x05
EVT_ENCRYPTION_CHANGE = 0x08
EVT_COMMAND_COMPLETE = 0x0E
EVT_COMMAND_STATUS = 0x0F
EVT_NUMBER_OF_COMPLETED_PACKETS = 0x13
EVT_LE_META = 0x3E

# Subevent codes carried in the first parameter byte of an LE Meta event.
LE_CONNECTION_COMPLETE = 0x01
LE_CONNECTION_UPDATE_COMPLETE = 0x03
LE_LONG_TERM_KEY_REQUEST = 0x05
LE_ENHANCED_CONNECTION_COMPLETE = 0x0A

# Link layer roles reported by LE Connection Complete.
ROLE_CENTRAL = 0x00
ROLE_PERIPHERAL = 0x01

# Packet boundary flags in an ACL header. LE links carry only the
# non-flushable forms, so a payload starts with FIRST and any further
# fragments of the same payload use CONTINUING.
ACL_PB_FIRST = 0x00
ACL_PB_CONTINUING = 0x01

# The smallest LE ACL payload every controller must accept. Used until the
# controller reports its real capacity.
LE_MIN_ACL_PAYLOAD = 27


@dataclass
class CommandComplete:
    opcode: int
    status: int
    parameters: bytes = b""


@dataclass
class CommandStatus:
    opcode: int
    status: int


@dataclass
class ConnectionComplete:
    status: int
    handle: int
    role: int
    peer_address_type: int
    peer_address: str
    # The address as it arrived, least significant octet first. Pairing mixes
    # it into the confirm value in exactly this order.
    peer_address_raw: bytes = b""
    # Connection interval in units of 1.25ms. Negotiated by the central, not
    # something this peripheral requests; worth surfacing since it bounds how
    # often a report can actually reach the air, regardless of how fast this
    # side calls send_acl_payload.
    interval_units: int = 0

    @property
    def interval_ms(self) -> float:
        return self.interval_units * 1.25


@dataclass
class DisconnectionComplete:
    status: int
    handle: int
    reason: int


@dataclass
class EncryptionChange:
    status: int
    handle: int
    enabled: int


@dataclass
class LongTermKeyRequest:
    handle: int
    random_number: bytes
    encrypted_diversifier: int


@dataclass
class NumberOfCompletedPackets:
    counts: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class ACLData:
    handle: int
    packet_boundary: int
    data: bytes


def format_address(octets) -> str:
    """Formats a little-endian 6-octet link layer address as a MAC string."""
    return ":".join(f"{b:02X}" for b in reversed(bytes(octets)))


def _u16(data, offset: int) -> int:
    """Reads a little-endian 16-bit value at the given offset."""
    return data[offset] | (data[offset + 1] << 8)


def parse_acl(packet):
    """
    Decodes one raw HCI ACL data packet.

    Returns None for packets that are not ACL data or whose declared payload
    length does not match what arrived.
    """
    data = bytes(packet)

    # H4 indicator, a combined handle and flags field, the payload length,
    # and then the payload itself.
    if len(data) < 5 or data[0] != HCI_ACLDATA_PKT:
        return None

    handle_flags = _u16(data, 1)
    length = _u16(data, 3)
    payload = data[5:]

    if len(payload) != length:
        return None

    # The handle occupies the low 12 bits; the boundary and broadcast flags
    # sit above it.
    return ACLData(
        handle=handle_flags & 0x0FFF,
        packet_boundary=(handle_flags >> 12) & 0x03,
        data=payload,
    )


def build_acl(handle: int, packet_boundary: int, payload: bytes) -> bytes:
    """Frames a payload as an HCI ACL data packet ready for the transport."""
    handle_flags = (handle & 0x0FFF) | ((packet_boundary & 0x03) << 12)
    return bytes([HCI_ACLDATA_PKT]) + \
        handle_flags.to_bytes(2, "little") + \
        len(payload).to_bytes(2, "little") + \
        bytes(payload)


def fragment_payload(payload: bytes, max_fragment: int) -> list[tuple[int, bytes]]:
    """
    Splits a payload into ACL-sized fragments paired with their boundary flag.

    An empty payload still yields one fragment, since a zero length ACL packet
    is how an empty L2CAP frame is carried.
    """
    if max_fragment < 1:
        raise ValueError("Maximum fragment size must be at least one byte.")

    if not payload:
        return [(ACL_PB_FIRST, b"")]

    fragments = []
    for offset in range(0, len(payload), max_fragment):
        boundary = ACL_PB_FIRST if offset == 0 else ACL_PB_CONTINUING
        fragments.append((boundary, payload[offset:offset + max_fragment]))
    return fragments


def parse_le_buffer_size(parameters: bytes):
    """
    Reads the LE ACL payload capacity from an LE Read Buffer Size response.

    Returns a (payload_length, total_packets) pair, or None if the controller
    reported failure or a truncated response. A payload length of zero means
    the controller shares its BR/EDR buffers and the caller should fall back
    to the legacy Read Buffer Size command.
    """
    if len(parameters) < 4 or parameters[0] != 0x00:
        return None
    return _u16(parameters, 1), parameters[3]


def parse_event(packet):
    """
    Decodes one raw HCI event packet.

    Returns a record for the events this stack acts on, or None for packets
    that are not events, are truncated, or carry an event we do not handle.
    """
    data = bytes(packet)

    # An event packet is the H4 indicator, the event code, the parameter
    # length, and then that many parameter bytes.
    if len(data) < 3 or data[0] != HCI_EVENT_PKT:
        return None

    code = data[1]
    params = data[3:3 + data[2]]

    if code == EVT_COMMAND_COMPLETE and len(params) >= 3:
        # Number of allowed command packets, opcode, then return parameters.
        # The first return parameter is a status byte for almost every command.
        return CommandComplete(
            opcode=_u16(params, 1),
            status=params[3] if len(params) >= 4 else 0x00,
            parameters=params[3:],
        )

    if code == EVT_COMMAND_STATUS and len(params) >= 4:
        return CommandStatus(opcode=_u16(params, 2), status=params[0])

    if code == EVT_DISCONNECTION_COMPLETE and len(params) >= 4:
        return DisconnectionComplete(
            status=params[0],
            handle=_u16(params, 1),
            reason=params[3],
        )

    if code == EVT_ENCRYPTION_CHANGE and len(params) >= 4:
        return EncryptionChange(
            status=params[0],
            handle=_u16(params, 1),
            enabled=params[3],
        )

    if code == EVT_NUMBER_OF_COMPLETED_PACKETS and len(params) >= 1:
        # A count of handles, followed by that many handle/count pairs. These
        # release controller buffer slots and gate how much ACL data we may send.
        counts = []
        for i in range(params[0]):
            entry = 1 + i * 4
            if entry + 3 < len(params):
                counts.append((_u16(params, entry), _u16(params, entry + 2)))
        return NumberOfCompletedPackets(counts=counts)

    if code == EVT_LE_META and len(params) >= 1:
        return _parse_le_meta(params[0], params[1:])

    return None


def _parse_le_meta(subevent: int, data: bytes):
    """Decodes the LE Meta subevents this stack acts on."""
    # The legacy and enhanced forms of Connection Complete agree on every
    # field up to the peer address, so one decoder covers both.
    if subevent in (LE_CONNECTION_COMPLETE, LE_ENHANCED_CONNECTION_COMPLETE) and len(data) >= 12:
        return ConnectionComplete(
            status=data[0],
            handle=_u16(data, 1),
            role=data[3],
            peer_address_type=data[4],
            peer_address=format_address(data[5:11]),
            peer_address_raw=bytes(data[5:11]),
            # Interval follows the peer address in both the legacy and
            # enhanced forms; only absent if the event were truncated.
            interval_units=_u16(data, 11) if len(data) >= 13 else 0,
        )

    if subevent == LE_LONG_TERM_KEY_REQUEST and len(data) >= 12:
        return LongTermKeyRequest(
            handle=_u16(data, 0),
            random_number=data[2:10],
            encrypted_diversifier=_u16(data, 10),
        )

    return None
