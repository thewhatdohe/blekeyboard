"""
Attribute Protocol encoding.

ATT is a request/response protocol carried on a fixed L2CAP channel. Every
PDU begins with a one octet opcode; the remainder depends on the opcode.
This module owns the opcode and error definitions and the construction of
the responses the server sends.
"""

# Requests a client may send, and the responses that answer them.
ERROR_RESPONSE = 0x01
EXCHANGE_MTU_REQUEST = 0x02
EXCHANGE_MTU_RESPONSE = 0x03
FIND_INFORMATION_REQUEST = 0x04
FIND_INFORMATION_RESPONSE = 0x05
FIND_BY_TYPE_VALUE_REQUEST = 0x06
FIND_BY_TYPE_VALUE_RESPONSE = 0x07
READ_BY_TYPE_REQUEST = 0x08
READ_BY_TYPE_RESPONSE = 0x09
READ_REQUEST = 0x0A
READ_RESPONSE = 0x0B
READ_BLOB_REQUEST = 0x0C
READ_BLOB_RESPONSE = 0x0D
READ_BY_GROUP_TYPE_REQUEST = 0x10
READ_BY_GROUP_TYPE_RESPONSE = 0x11
WRITE_REQUEST = 0x12
WRITE_RESPONSE = 0x13
HANDLE_VALUE_NOTIFICATION = 0x1B
HANDLE_VALUE_INDICATION = 0x1D
HANDLE_VALUE_CONFIRMATION = 0x1E
WRITE_COMMAND = 0x52

# Error codes carried in an Error Response.
ERR_INVALID_HANDLE = 0x01
ERR_READ_NOT_PERMITTED = 0x02
ERR_WRITE_NOT_PERMITTED = 0x03
ERR_INVALID_PDU = 0x04
ERR_INSUFFICIENT_AUTHENTICATION = 0x05
ERR_REQUEST_NOT_SUPPORTED = 0x06
ERR_INVALID_OFFSET = 0x07
ERR_ATTRIBUTE_NOT_FOUND = 0x0A
ERR_INVALID_ATTRIBUTE_VALUE_LENGTH = 0x0D
ERR_UNLIKELY_ERROR = 0x0E
ERR_INSUFFICIENT_ENCRYPTION = 0x0F
ERR_UNSUPPORTED_GROUP_TYPE = 0x10

# Formats reported by a Find Information Response.
FORMAT_UUID16 = 0x01
FORMAT_UUID128 = 0x02

# Every ATT implementation must support at least this much, and it is the
# value in force until a client negotiates something larger.
DEFAULT_MTU = 23

# A command has its high bit set and is never answered, not even on error.
COMMAND_FLAG = 0x40


def is_command(opcode: int) -> bool:
    """True if the opcode denotes a command, which must not be responded to."""
    return bool(opcode & COMMAND_FLAG)


def uuid_to_bytes(uuid) -> bytes:
    """Encodes a 16-bit UUID given as an int, or passes 128-bit bytes through."""
    if isinstance(uuid, int):
        return uuid.to_bytes(2, "little")
    return bytes(uuid)


def error_response(request_opcode: int, handle: int, error_code: int) -> bytes:
    """Builds the Error Response that rejects a request."""
    return bytes([ERROR_RESPONSE, request_opcode]) \
        + handle.to_bytes(2, "little") \
        + bytes([error_code])


def exchange_mtu_response(server_mtu: int) -> bytes:
    return bytes([EXCHANGE_MTU_RESPONSE]) + server_mtu.to_bytes(2, "little")


def read_response(value: bytes) -> bytes:
    return bytes([READ_RESPONSE]) + bytes(value)


def read_blob_response(value: bytes) -> bytes:
    return bytes([READ_BLOB_RESPONSE]) + bytes(value)


def write_response() -> bytes:
    return bytes([WRITE_RESPONSE])


def handle_value_notification(handle: int, value: bytes) -> bytes:
    return bytes([HANDLE_VALUE_NOTIFICATION]) + handle.to_bytes(2, "little") + bytes(value)


def find_information_response(entries) -> bytes:
    """
    Builds a Find Information Response from (handle, uuid) pairs.

    A single response carries one UUID width, so the caller is expected to
    have grouped the entries accordingly.
    """
    encoded = [(handle, uuid_to_bytes(uuid)) for handle, uuid in entries]
    fmt = FORMAT_UUID16 if len(encoded[0][1]) == 2 else FORMAT_UUID128

    body = b"".join(handle.to_bytes(2, "little") + uuid for handle, uuid in encoded)
    return bytes([FIND_INFORMATION_RESPONSE, fmt]) + body


def find_by_type_value_response(ranges) -> bytes:
    """Builds a Find By Type Value Response from (found_handle, group_end) pairs."""
    body = b"".join(
        found.to_bytes(2, "little") + end.to_bytes(2, "little")
        for found, end in ranges
    )
    return bytes([FIND_BY_TYPE_VALUE_RESPONSE]) + body


def read_by_type_response(entries) -> bytes:
    """
    Builds a Read By Type Response from (handle, value) pairs.

    Every record in one response has the same length, which is stated once in
    the header, so the caller must supply equal-length values.
    """
    record_length = 2 + len(entries[0][1])
    body = b"".join(handle.to_bytes(2, "little") + bytes(value) for handle, value in entries)
    return bytes([READ_BY_TYPE_RESPONSE, record_length]) + body


def read_by_group_type_response(entries) -> bytes:
    """
    Builds a Read By Group Type Response from (start, end, value) triples.

    As with Read By Type, one response carries records of a single length.
    """
    record_length = 4 + len(entries[0][2])
    body = b"".join(
        start.to_bytes(2, "little") + end.to_bytes(2, "little") + bytes(value)
        for start, end, value in entries
    )
    return bytes([READ_BY_GROUP_TYPE_RESPONSE, record_length]) + body
