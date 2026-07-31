import pytest

from blekeyboard import att
from blekeyboard.gatt import (
    PROP_NOTIFY,
    PROP_READ,
    PROP_WRITE,
    UUID_CHARACTERISTIC,
    UUID_CLIENT_CHARACTERISTIC_CONFIGURATION,
    UUID_PRIMARY_SERVICE,
    AttributeDatabase,
    GattServer,
)
from blekeyboard.profile import (
    APPEARANCE_KEYBOARD,
    UUID_APPEARANCE,
    UUID_DEVICE_NAME,
    UUID_GAP_SERVICE,
    build_database,
)


def read_by_group_type(start=0x0001, end=0xFFFF, uuid=UUID_PRIMARY_SERVICE):
    return bytes([att.READ_BY_GROUP_TYPE_REQUEST]) \
        + start.to_bytes(2, "little") + end.to_bytes(2, "little") \
        + uuid.to_bytes(2, "little")


def read_by_type(uuid, start=0x0001, end=0xFFFF):
    return bytes([att.READ_BY_TYPE_REQUEST]) \
        + start.to_bytes(2, "little") + end.to_bytes(2, "little") \
        + uuid.to_bytes(2, "little")


def find_information(start=0x0001, end=0xFFFF):
    return bytes([att.FIND_INFORMATION_REQUEST]) \
        + start.to_bytes(2, "little") + end.to_bytes(2, "little")


def read(handle):
    return bytes([att.READ_REQUEST]) + handle.to_bytes(2, "little")


def write(handle, value, command=False):
    opcode = att.WRITE_COMMAND if command else att.WRITE_REQUEST
    return bytes([opcode]) + handle.to_bytes(2, "little") + bytes(value)


@pytest.fixture
def database():
    return build_database("BLE-Ducky")


@pytest.fixture
def server(database):
    return GattServer(database)


class TestDatabaseConstruction:
    def test_handles_start_at_one_and_increment(self, database):
        assert [a.handle for a in database.attributes] == list(
            range(1, len(database.attributes) + 1))

    def test_characteristic_declaration_points_at_its_value(self):
        db = AttributeDatabase()
        db.add_service(0x1800)
        declaration, value = db.add_characteristic(0x2A00, PROP_READ, b"name")

        assert declaration.uuid == UUID_CHARACTERISTIC
        assert declaration.value[0] == PROP_READ
        assert int.from_bytes(declaration.value[1:3], "little") == value.handle
        assert declaration.value[3:] == b"\x00\x2A"

    def test_group_end_stops_before_the_next_service(self, database):
        gap = database.attributes[0]
        # GAP holds its declaration plus two characteristics, each of which is
        # a declaration and a value attribute.
        assert database.group_end_handle(gap) == 5

    def test_group_end_of_the_last_service_is_the_final_handle(self, database):
        gatt_service = [a for a in database.attributes
                        if a.uuid == UUID_PRIMARY_SERVICE][-1]
        assert database.group_end_handle(gatt_service) == database.attributes[-1].handle

    def test_writable_characteristic_is_marked_writable(self):
        db = AttributeDatabase()
        db.add_service(0x1800)
        _, value = db.add_characteristic(0x2A00, PROP_READ | PROP_WRITE, b"")
        assert value.writable


class TestMtuExchange:
    def test_server_answers_with_its_own_mtu(self, server):
        response = server.handle_pdu(bytes([att.EXCHANGE_MTU_REQUEST, 0x0F, 0x02]))
        assert response[0] == att.EXCHANGE_MTU_RESPONSE
        assert int.from_bytes(response[1:3], "little") == server.server_mtu

    def test_smaller_of_the_two_mtus_is_adopted(self, server):
        server.server_mtu = 100
        server.handle_pdu(bytes([att.EXCHANGE_MTU_REQUEST, 50, 0x00]))
        assert server.mtu == 50

    def test_negotiated_mtu_never_drops_below_the_default(self, server):
        server.handle_pdu(bytes([att.EXCHANGE_MTU_REQUEST, 5, 0x00]))
        assert server.mtu == att.DEFAULT_MTU

    def test_truncated_request_is_rejected(self, server):
        response = server.handle_pdu(bytes([att.EXCHANGE_MTU_REQUEST]))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_INVALID_PDU


class TestServiceDiscovery:
    def test_primary_services_are_returned_with_their_ranges(self, server):
        response = server.handle_pdu(read_by_group_type())
        assert response[0] == att.READ_BY_GROUP_TYPE_RESPONSE

        record_length = response[1]
        assert record_length == 6  # two handles plus a 16-bit UUID

        start = int.from_bytes(response[2:4], "little")
        end = int.from_bytes(response[4:6], "little")
        uuid = int.from_bytes(response[6:8], "little")
        assert (start, end, uuid) == (0x0001, 0x0005, UUID_GAP_SERVICE)

    def test_discovery_continues_past_the_first_service(self, server):
        response = server.handle_pdu(read_by_group_type(start=0x0006))
        assert response[0] == att.READ_BY_GROUP_TYPE_RESPONSE

    def test_exhausted_range_reports_attribute_not_found(self, server):
        response = server.handle_pdu(read_by_group_type(start=0x00FF, end=0xFFFF))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_ATTRIBUTE_NOT_FOUND

    def test_non_service_group_type_is_refused(self, server):
        response = server.handle_pdu(read_by_group_type(uuid=UUID_CHARACTERISTIC))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_UNSUPPORTED_GROUP_TYPE

    def test_inverted_handle_range_is_rejected(self, server):
        response = server.handle_pdu(read_by_group_type(start=0x0010, end=0x0001))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_INVALID_HANDLE

    def test_zero_start_handle_is_rejected(self, server):
        response = server.handle_pdu(read_by_group_type(start=0x0000))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_INVALID_HANDLE


class TestCharacteristicDiscovery:
    def test_characteristic_declarations_are_returned(self, server):
        response = server.handle_pdu(read_by_type(UUID_CHARACTERISTIC))
        assert response[0] == att.READ_BY_TYPE_RESPONSE

        record_length = response[1]
        records = response[2:]
        assert len(records) % record_length == 0

        first = records[:record_length]
        handle = int.from_bytes(first[0:2], "little")
        assert handle == 0x0002
        assert first[2] == PROP_READ

    def test_response_never_exceeds_the_negotiated_mtu(self, server):
        response = server.handle_pdu(read_by_type(UUID_CHARACTERISTIC))
        assert len(response) <= server.mtu

    def test_missing_type_reports_attribute_not_found(self, server):
        response = server.handle_pdu(read_by_type(0x2AFF))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_ATTRIBUTE_NOT_FOUND


class TestDescriptorDiscovery:
    def test_find_information_lists_handles_and_types(self, server):
        response = server.handle_pdu(find_information())
        assert response[0] == att.FIND_INFORMATION_RESPONSE
        assert response[1] == att.FORMAT_UUID16

        assert int.from_bytes(response[2:4], "little") == 0x0001
        assert int.from_bytes(response[4:6], "little") == UUID_PRIMARY_SERVICE

    def test_response_never_exceeds_the_negotiated_mtu(self, server):
        assert len(server.handle_pdu(find_information())) <= server.mtu

    def test_range_beyond_the_table_reports_attribute_not_found(self, server):
        response = server.handle_pdu(find_information(start=0x00F0, end=0x00FF))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_ATTRIBUTE_NOT_FOUND


class TestReads:
    def test_device_name_is_readable(self, server, database):
        handle = _value_handle(database, UUID_DEVICE_NAME)
        response = server.handle_pdu(read(handle))
        assert response[0] == att.READ_RESPONSE
        assert response[1:] == b"BLE-Ducky"

    def test_appearance_reports_a_keyboard(self, server, database):
        handle = _value_handle(database, UUID_APPEARANCE)
        response = server.handle_pdu(read(handle))
        assert int.from_bytes(response[1:3], "little") == APPEARANCE_KEYBOARD

    def test_unknown_handle_is_rejected(self, server):
        response = server.handle_pdu(read(0x00FF))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_INVALID_HANDLE

    def test_value_is_truncated_to_the_negotiated_mtu(self):
        db = AttributeDatabase()
        db.add_service(0x1800)
        _, value = db.add_characteristic(0x2A00, PROP_READ, b"x" * 100)

        server = GattServer(db)
        response = server.handle_pdu(read(value.handle))
        assert len(response) == server.mtu

    def test_blob_read_resumes_from_an_offset(self):
        db = AttributeDatabase()
        db.add_service(0x1800)
        _, value = db.add_characteristic(0x2A00, PROP_READ, bytes(range(60)))

        server = GattServer(db)
        request = bytes([att.READ_BLOB_REQUEST]) \
            + value.handle.to_bytes(2, "little") + (22).to_bytes(2, "little")
        response = server.handle_pdu(request)

        assert response[0] == att.READ_BLOB_RESPONSE
        assert response[1:] == bytes(range(60))[22:22 + server.mtu - 1]

    def test_blob_offset_past_the_value_is_rejected(self, server, database):
        handle = _value_handle(database, UUID_DEVICE_NAME)
        request = bytes([att.READ_BLOB_REQUEST]) \
            + handle.to_bytes(2, "little") + (99).to_bytes(2, "little")
        response = server.handle_pdu(request)
        assert response[4] == att.ERR_INVALID_OFFSET


class TestWrites:
    def test_write_updates_the_value_and_is_acknowledged(self):
        db = AttributeDatabase()
        db.add_service(0x1800)
        _, value = db.add_characteristic(0x2A00, PROP_READ | PROP_WRITE, b"old")

        server = GattServer(db)
        response = server.handle_pdu(write(value.handle, b"new"))
        assert response == bytes([att.WRITE_RESPONSE])
        assert value.value == b"new"

    def test_write_command_is_applied_without_a_response(self):
        db = AttributeDatabase()
        db.add_service(0x1800)
        _, value = db.add_characteristic(0x2A00, PROP_READ | PROP_WRITE, b"old")

        server = GattServer(db)
        assert server.handle_pdu(write(value.handle, b"new", command=True)) is None
        assert value.value == b"new"

    def test_write_to_a_read_only_attribute_is_refused(self, server, database):
        handle = _value_handle(database, UUID_DEVICE_NAME)
        response = server.handle_pdu(write(handle, b"nope"))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_WRITE_NOT_PERMITTED

    def test_write_callback_receives_the_new_value(self):
        seen = []
        db = AttributeDatabase()
        db.add_service(0x1800)
        descriptor = db.add_descriptor(
            UUID_CLIENT_CHARACTERISTIC_CONFIGURATION,
            b"\x00\x00",
            writable=True,
            on_write=seen.append,
        )

        GattServer(db).handle_pdu(write(descriptor.handle, b"\x01\x00"))
        assert seen == [b"\x01\x00"]

    def test_failed_write_command_stays_silent(self, server, database):
        # A command is never answered, not even to report a failure.
        handle = _value_handle(database, UUID_DEVICE_NAME)
        assert server.handle_pdu(write(handle, b"nope", command=True)) is None


class TestEncryptionGating:
    def _protected_server(self):
        db = AttributeDatabase()
        db.add_service(0x1812)
        _, value = db.add_characteristic(
            0x2A4D,
            PROP_READ | PROP_NOTIFY,
            b"\x00" * 8,
            requires_encryption=True,
        )
        return GattServer(db), value

    def test_protected_read_is_refused_on_an_unencrypted_link(self):
        server, value = self._protected_server()
        response = server.handle_pdu(read(value.handle))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_INSUFFICIENT_ENCRYPTION

    def test_protected_read_succeeds_once_encrypted(self):
        server, value = self._protected_server()
        server.encrypted = True
        response = server.handle_pdu(read(value.handle))
        assert response[0] == att.READ_RESPONSE


class TestUnsupportedRequests:
    def test_unknown_request_is_refused(self, server):
        # 0x20 is unassigned and lacks the command bit, so it is a request.
        response = server.handle_pdu(bytes([0x20]))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_REQUEST_NOT_SUPPORTED

    def test_indication_from_a_client_is_refused(self, server):
        # Indications travel server to client, so one arriving here is not
        # something this server implements.
        response = server.handle_pdu(bytes([att.HANDLE_VALUE_INDICATION, 0x01, 0x00]))
        assert response[0] == att.ERROR_RESPONSE
        assert response[4] == att.ERR_REQUEST_NOT_SUPPORTED

    @pytest.mark.parametrize("opcode", [0x7F, 0xFF, att.WRITE_COMMAND | 0x80])
    def test_commands_are_never_answered(self, server, opcode):
        # Bit 6 marks an opcode as a command, which gets no reply even when
        # it cannot be carried out.
        assert att.is_command(opcode)
        assert server.handle_pdu(bytes([opcode])) is None

    def test_empty_pdu_is_ignored(self, server):
        assert server.handle_pdu(b"") is None


class TestFullClientDiscovery:
    """Walks the sequence a real client performs after connecting."""

    def test_a_client_can_enumerate_everything_and_read_a_value(self, server):
        server.handle_pdu(bytes([att.EXCHANGE_MTU_REQUEST]) + (527).to_bytes(2, "little"))

        services = _walk_services(server)
        assert services == [
            (0x0001, 0x0005, UUID_GAP_SERVICE),
            (0x0006, 0x0006, 0x1801),
        ]

        characteristics = _walk_characteristics(server)
        assert [uuid for _, uuid in characteristics] == [UUID_DEVICE_NAME, UUID_APPEARANCE]

        name_handle = dict((uuid, handle) for handle, uuid in characteristics)[UUID_DEVICE_NAME]
        response = server.handle_pdu(read(name_handle))
        assert response[1:] == b"BLE-Ducky"

    def test_every_discovery_response_fits_the_negotiated_mtu(self, server):
        server.handle_pdu(bytes([att.EXCHANGE_MTU_REQUEST]) + (527).to_bytes(2, "little"))

        for pdu in (read_by_group_type(), read_by_type(UUID_CHARACTERISTIC), find_information()):
            assert len(server.handle_pdu(pdu)) <= server.mtu


def _walk_services(server):
    """Repeats Read By Group Type until the server reports nothing further."""
    found = []
    start = 0x0001
    while start <= 0xFFFF:
        response = server.handle_pdu(read_by_group_type(start=start))
        if response[0] == att.ERROR_RESPONSE:
            break

        record_length = response[1]
        records = response[2:]
        for offset in range(0, len(records), record_length):
            record = records[offset:offset + record_length]
            found.append((
                int.from_bytes(record[0:2], "little"),
                int.from_bytes(record[2:4], "little"),
                int.from_bytes(record[4:], "little"),
            ))

        if found[-1][1] >= 0xFFFF:
            break
        start = found[-1][1] + 1
    return found


def _walk_characteristics(server):
    """Repeats Read By Type, returning (value_handle, uuid) for each characteristic."""
    found = []
    start = 0x0001
    while start <= 0xFFFF:
        response = server.handle_pdu(read_by_type(UUID_CHARACTERISTIC, start=start))
        if response[0] == att.ERROR_RESPONSE:
            break

        record_length = response[1]
        records = response[2:]
        last_declaration = None
        for offset in range(0, len(records), record_length):
            record = records[offset:offset + record_length]
            last_declaration = int.from_bytes(record[0:2], "little")
            found.append((
                int.from_bytes(record[3:5], "little"),
                int.from_bytes(record[5:], "little"),
            ))

        if last_declaration is None or last_declaration >= 0xFFFF:
            break
        start = last_declaration + 1
    return found


def _value_handle(database, uuid):
    """Finds the handle holding a characteristic's value."""
    for attribute in database.attributes:
        if attribute.uuid == uuid:
            return attribute.handle
    raise AssertionError(f"no attribute with UUID 0x{uuid:04X}")
