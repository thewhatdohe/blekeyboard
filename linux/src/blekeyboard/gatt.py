"""
The attribute database and the server that answers ATT requests against it.

A GATT server is an ordered table of attributes, each with a handle, a type
and a value. Services and characteristics are not separate objects in the
protocol; they are ordinary attributes whose type marks them as declarations
and whose value describes what follows.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from blekeyboard import att

# Attribute types that declare structure rather than carry user data.
UUID_PRIMARY_SERVICE = 0x2800
UUID_SECONDARY_SERVICE = 0x2801
UUID_INCLUDE = 0x2802
UUID_CHARACTERISTIC = 0x2803

# Descriptor types.
UUID_CLIENT_CHARACTERISTIC_CONFIGURATION = 0x2902
UUID_REPORT_REFERENCE = 0x2908

# Characteristic property bits, carried in the declaration value.
PROP_BROADCAST = 0x01
PROP_READ = 0x02
PROP_WRITE_WITHOUT_RESPONSE = 0x04
PROP_WRITE = 0x08
PROP_NOTIFY = 0x10
PROP_INDICATE = 0x20

# Bit a client sets in a Client Characteristic Configuration descriptor to
# subscribe to notifications.
CCCD_NOTIFICATION_ENABLED = 0x0001

SERVICE_DECLARATION_TYPES = (UUID_PRIMARY_SERVICE, UUID_SECONDARY_SERVICE)


@dataclass
class Attribute:
    handle: int
    uuid: Union[int, bytes]
    value: bytes = b""
    readable: bool = True
    writable: bool = False
    requires_encryption: bool = False
    on_write: Optional[Callable[[bytes], None]] = field(default=None, repr=False)

    @property
    def uuid_bytes(self) -> bytes:
        return att.uuid_to_bytes(self.uuid)


class AttributeDatabase:
    """An ordered attribute table with handles assigned on insertion."""

    def __init__(self):
        self.attributes: list[Attribute] = []

    def _append(self, uuid, value=b"", **kwargs) -> Attribute:
        attribute = Attribute(
            handle=len(self.attributes) + 1,
            uuid=uuid,
            value=bytes(value),
            **kwargs,
        )
        self.attributes.append(attribute)
        return attribute

    def add_service(self, uuid, primary: bool = True) -> Attribute:
        """Declares a service. Its value is the service UUID."""
        declaration = UUID_PRIMARY_SERVICE if primary else UUID_SECONDARY_SERVICE
        return self._append(declaration, att.uuid_to_bytes(uuid))

    def add_characteristic(
        self,
        uuid,
        properties: int,
        value: bytes = b"",
        writable: bool = False,
        requires_encryption: bool = False,
        on_write=None,
    ):
        """
        Declares a characteristic and the attribute holding its value.

        The declaration value is the property bits, the handle the value lives
        at, and the characteristic UUID. That value handle is only known once
        the declaration itself has been placed, so it is filled in afterwards.
        """
        declaration = self._append(UUID_CHARACTERISTIC)
        value_attribute = self._append(
            uuid,
            value,
            readable=bool(properties & PROP_READ),
            writable=writable or bool(properties & (PROP_WRITE | PROP_WRITE_WITHOUT_RESPONSE)),
            requires_encryption=requires_encryption,
            on_write=on_write,
        )

        declaration.value = bytes([properties]) \
            + value_attribute.handle.to_bytes(2, "little") \
            + att.uuid_to_bytes(uuid)

        return declaration, value_attribute

    def add_descriptor(self, uuid, value=b"", **kwargs) -> Attribute:
        return self._append(uuid, value, **kwargs)

    def find(self, handle: int) -> Optional[Attribute]:
        for attribute in self.attributes:
            if attribute.handle == handle:
                return attribute
        return None

    def in_range(self, start: int, end: int):
        return [a for a in self.attributes if start <= a.handle <= end]

    def find_descriptor(self, value_handle: int, descriptor_uuid) -> Optional[Attribute]:
        """
        Finds a descriptor belonging to the characteristic at `value_handle`.

        A characteristic's descriptors are the attributes following its value,
        up to whatever declares the next characteristic or service. Searching
        that way, rather than assuming a fixed offset, matches how a real
        client would locate a descriptor by handle range.
        """
        for attribute in self.attributes:
            if attribute.handle <= value_handle:
                continue
            if attribute.uuid in (UUID_CHARACTERISTIC, *SERVICE_DECLARATION_TYPES):
                break
            if attribute.uuid == descriptor_uuid:
                return attribute
        return None

    def group_end_handle(self, service: Attribute) -> int:
        """
        Last handle belonging to a service.

        A service owns every attribute up to the next service declaration, so
        the group ends just before it, or at the end of the table.
        """
        seen = False
        for attribute in self.attributes:
            if attribute is service:
                seen = True
                continue
            if seen and attribute.uuid in SERVICE_DECLARATION_TYPES:
                return attribute.handle - 1
        return self.attributes[-1].handle if self.attributes else service.handle


class GattServer:
    """Answers ATT requests against an attribute database."""

    def __init__(self, database: AttributeDatabase, server_mtu: int = att.DEFAULT_MTU):
        self.database = database
        self.server_mtu = server_mtu
        self.mtu = att.DEFAULT_MTU
        self.encrypted = False
        # The client's requested MTU, unclamped by server_mtu - unlike `mtu`,
        # which both sides actually use. Kept only as a host-identification
        # signal (see hostprofile.py); nothing here should read it for framing.
        self.client_requested_mtu = None

    def handle_pdu(self, pdu: bytes) -> Optional[bytes]:
        """
        Processes one inbound ATT PDU.

        Returns the PDU to send back, or None when the request was a command,
        which is never answered.
        """
        if not pdu:
            return None

        opcode = pdu[0]
        parameters = pdu[1:]

        handler = self._HANDLERS.get(opcode)
        if handler is None:
            # Commands are silently dropped; requests get a refusal.
            if att.is_command(opcode):
                return None
            return att.error_response(opcode, 0x0000, att.ERR_REQUEST_NOT_SUPPORTED)

        return handler(self, opcode, parameters)

    def _handle_exchange_mtu(self, opcode, parameters):
        if len(parameters) < 2:
            return att.error_response(opcode, 0x0000, att.ERR_INVALID_PDU)

        client_mtu = int.from_bytes(parameters[0:2], "little")
        self.client_requested_mtu = client_mtu

        # Both sides adopt the smaller of the two, and neither may go below
        # the default.
        self.mtu = max(att.DEFAULT_MTU, min(client_mtu, self.server_mtu))
        return att.exchange_mtu_response(self.server_mtu)

    def _handle_find_information(self, opcode, parameters):
        if len(parameters) < 4:
            return att.error_response(opcode, 0x0000, att.ERR_INVALID_PDU)

        start = int.from_bytes(parameters[0:2], "little")
        end = int.from_bytes(parameters[2:4], "little")
        if not _is_valid_range(start, end):
            return att.error_response(opcode, start, att.ERR_INVALID_HANDLE)

        found = self.database.in_range(start, end)
        if not found:
            return att.error_response(opcode, start, att.ERR_ATTRIBUTE_NOT_FOUND)

        # One response carries a single UUID width, so stop at the first
        # attribute whose width differs from the first.
        width = len(found[0].uuid_bytes)
        budget = self.mtu - 2
        entries = []
        for attribute in found:
            if len(attribute.uuid_bytes) != width or budget < 2 + width:
                break
            entries.append((attribute.handle, attribute.uuid))
            budget -= 2 + width

        if not entries:
            return att.error_response(opcode, start, att.ERR_ATTRIBUTE_NOT_FOUND)
        return att.find_information_response(entries)

    def _handle_find_by_type_value(self, opcode, parameters):
        if len(parameters) < 6:
            return att.error_response(opcode, 0x0000, att.ERR_INVALID_PDU)

        start = int.from_bytes(parameters[0:2], "little")
        end = int.from_bytes(parameters[2:4], "little")
        attribute_type = int.from_bytes(parameters[4:6], "little")
        wanted = parameters[6:]

        if not _is_valid_range(start, end):
            return att.error_response(opcode, start, att.ERR_INVALID_HANDLE)

        budget = self.mtu - 1
        ranges = []
        for attribute in self.database.in_range(start, end):
            if attribute.uuid != attribute_type or attribute.value != wanted:
                continue
            if budget < 4:
                break
            group_end = self.database.group_end_handle(attribute) \
                if attribute.uuid in SERVICE_DECLARATION_TYPES else attribute.handle
            ranges.append((attribute.handle, group_end))
            budget -= 4

        if not ranges:
            return att.error_response(opcode, start, att.ERR_ATTRIBUTE_NOT_FOUND)
        return att.find_by_type_value_response(ranges)

    def _handle_read_by_type(self, opcode, parameters):
        parsed = _parse_typed_range(parameters)
        if parsed is None:
            return att.error_response(opcode, 0x0000, att.ERR_INVALID_PDU)

        start, end, wanted_uuid = parsed
        if not _is_valid_range(start, end):
            return att.error_response(opcode, start, att.ERR_INVALID_HANDLE)

        # A value may be truncated to fit, but every record in the response
        # must then be the same length.
        max_value = min(self.mtu - 4, 253)
        entries = []
        length = None
        for attribute in self.database.in_range(start, end):
            if att.uuid_to_bytes(attribute.uuid) != wanted_uuid:
                continue

            denial = self._read_denial(attribute)
            if denial is not None:
                # Refuse the whole request only if nothing was collected yet.
                if entries:
                    break
                return att.error_response(opcode, attribute.handle, denial)

            value = attribute.value[:max_value]
            if length is None:
                length = len(value)
            elif len(value) != length:
                break

            if (len(entries) + 1) * (2 + length) > self.mtu - 2:
                break
            entries.append((attribute.handle, value))

        if not entries:
            return att.error_response(opcode, start, att.ERR_ATTRIBUTE_NOT_FOUND)
        return att.read_by_type_response(entries)

    def _handle_read_by_group_type(self, opcode, parameters):
        parsed = _parse_typed_range(parameters)
        if parsed is None:
            return att.error_response(opcode, 0x0000, att.ERR_INVALID_PDU)

        start, end, wanted_uuid = parsed
        if not _is_valid_range(start, end):
            return att.error_response(opcode, start, att.ERR_INVALID_HANDLE)

        # Only service declarations form groups.
        if wanted_uuid not in (
            att.uuid_to_bytes(UUID_PRIMARY_SERVICE),
            att.uuid_to_bytes(UUID_SECONDARY_SERVICE),
        ):
            return att.error_response(opcode, start, att.ERR_UNSUPPORTED_GROUP_TYPE)

        max_value = min(self.mtu - 6, 251)
        entries = []
        length = None
        for attribute in self.database.in_range(start, end):
            if att.uuid_to_bytes(attribute.uuid) != wanted_uuid:
                continue

            value = attribute.value[:max_value]
            if length is None:
                length = len(value)
            elif len(value) != length:
                break

            if (len(entries) + 1) * (4 + length) > self.mtu - 2:
                break
            entries.append((attribute.handle, self.database.group_end_handle(attribute), value))

        if not entries:
            return att.error_response(opcode, start, att.ERR_ATTRIBUTE_NOT_FOUND)
        return att.read_by_group_type_response(entries)

    def _handle_read(self, opcode, parameters):
        if len(parameters) < 2:
            return att.error_response(opcode, 0x0000, att.ERR_INVALID_PDU)

        handle = int.from_bytes(parameters[0:2], "little")
        attribute = self.database.find(handle)
        if attribute is None:
            return att.error_response(opcode, handle, att.ERR_INVALID_HANDLE)

        denial = self._read_denial(attribute)
        if denial is not None:
            return att.error_response(opcode, handle, denial)

        return att.read_response(attribute.value[:self.mtu - 1])

    def _handle_read_blob(self, opcode, parameters):
        if len(parameters) < 4:
            return att.error_response(opcode, 0x0000, att.ERR_INVALID_PDU)

        handle = int.from_bytes(parameters[0:2], "little")
        offset = int.from_bytes(parameters[2:4], "little")
        attribute = self.database.find(handle)
        if attribute is None:
            return att.error_response(opcode, handle, att.ERR_INVALID_HANDLE)

        denial = self._read_denial(attribute)
        if denial is not None:
            return att.error_response(opcode, handle, denial)

        if offset > len(attribute.value):
            return att.error_response(opcode, handle, att.ERR_INVALID_OFFSET)

        return att.read_blob_response(attribute.value[offset:offset + self.mtu - 1])

    def _handle_write(self, opcode, parameters):
        if len(parameters) < 2:
            return att.error_response(opcode, 0x0000, att.ERR_INVALID_PDU)

        handle = int.from_bytes(parameters[0:2], "little")
        value = parameters[2:]
        attribute = self.database.find(handle)

        is_command = att.is_command(opcode)
        if attribute is None:
            return None if is_command else att.error_response(
                opcode, handle, att.ERR_INVALID_HANDLE)

        if not attribute.writable:
            return None if is_command else att.error_response(
                opcode, handle, att.ERR_WRITE_NOT_PERMITTED)

        if attribute.requires_encryption and not self.encrypted:
            return None if is_command else att.error_response(
                opcode, handle, att.ERR_INSUFFICIENT_ENCRYPTION)

        attribute.value = bytes(value)
        if attribute.on_write is not None:
            attribute.on_write(attribute.value)

        return None if is_command else att.write_response()

    def is_subscribed(self, attribute: Attribute) -> bool:
        """
        Whether the client has enabled notifications on this characteristic.

        A client that has not written its Client Characteristic Configuration
        descriptor has not asked to receive anything, and sending it data
        anyway is not meaningful to it.
        """
        cccd = self.database.find_descriptor(
            attribute.handle, UUID_CLIENT_CHARACTERISTIC_CONFIGURATION)
        if cccd is None or len(cccd.value) < 2:
            return False
        return bool(int.from_bytes(cccd.value, "little") & CCCD_NOTIFICATION_ENABLED)

    def build_notification(self, attribute: Attribute, value: bytes) -> bytes:
        """Builds the ATT PDU for a Handle Value Notification of an attribute."""
        return att.handle_value_notification(attribute.handle, value)

    def _read_denial(self, attribute) -> Optional[int]:
        """The error code that blocks reading this attribute, if any."""
        if not attribute.readable:
            return att.ERR_READ_NOT_PERMITTED
        if attribute.requires_encryption and not self.encrypted:
            return att.ERR_INSUFFICIENT_ENCRYPTION
        return None

    _HANDLERS = {
        att.EXCHANGE_MTU_REQUEST: _handle_exchange_mtu,
        att.FIND_INFORMATION_REQUEST: _handle_find_information,
        att.FIND_BY_TYPE_VALUE_REQUEST: _handle_find_by_type_value,
        att.READ_BY_TYPE_REQUEST: _handle_read_by_type,
        att.READ_BY_GROUP_TYPE_REQUEST: _handle_read_by_group_type,
        att.READ_REQUEST: _handle_read,
        att.READ_BLOB_REQUEST: _handle_read_blob,
        att.WRITE_REQUEST: _handle_write,
        att.WRITE_COMMAND: _handle_write,
    }


def _is_valid_range(start: int, end: int) -> bool:
    """A handle range must be non-zero and not inverted."""
    return start != 0x0000 and start <= end


def _parse_typed_range(parameters: bytes):
    """Splits a start handle, end handle and 16 or 128 bit UUID."""
    if len(parameters) not in (6, 20):
        return None
    return (
        int.from_bytes(parameters[0:2], "little"),
        int.from_bytes(parameters[2:4], "little"),
        parameters[4:],
    )
