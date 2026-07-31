from blekeyboard.hci import (
    ROLE_PERIPHERAL,
    CommandComplete,
    ConnectionComplete,
    DisconnectionComplete,
    EncryptionChange,
    LongTermKeyRequest,
    NumberOfCompletedPackets,
    format_address,
    parse_event,
)


def test_rejects_non_event_packets():
    # An ACL data packet must not be decoded as an event.
    assert parse_event([0x02, 0x40, 0x00, 0x00, 0x00]) is None


def test_rejects_truncated_packets():
    assert parse_event([0x04, 0x3E]) is None


def test_command_complete_carries_opcode_and_status():
    # HCI Reset (0x0C03) completing successfully.
    event = parse_event([0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00])
    assert isinstance(event, CommandComplete)
    assert event.opcode == 0x0C03
    assert event.status == 0x00


def test_le_connection_complete_is_decoded():
    # Status 0, handle 0x0040, peripheral role, public peer AA:BB:CC:DD:EE:FF.
    packet = [
        0x04, 0x3E, 0x13, 0x01,
        0x00,
        0x40, 0x00,
        0x01,
        0x00,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
        0x18, 0x00,
        0x00, 0x00,
        0x48, 0x00,
        0x00,
    ]
    event = parse_event(packet)
    assert isinstance(event, ConnectionComplete)
    assert event.status == 0x00
    assert event.handle == 0x0040
    assert event.role == ROLE_PERIPHERAL
    assert event.peer_address == "AA:BB:CC:DD:EE:FF"


def test_enhanced_connection_complete_decodes_like_the_legacy_form():
    # Subevent 0x0A shares its leading fields with subevent 0x01.
    packet = [
        0x04, 0x3E, 0x1F, 0x0A,
        0x00,
        0x41, 0x00,
        0x01,
        0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    ] + [0x00] * 12 + [0x18, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00]
    event = parse_event(packet)
    assert isinstance(event, ConnectionComplete)
    assert event.handle == 0x0041
    assert event.peer_address == "66:55:44:33:22:11"


def test_disconnection_complete_reports_reason():
    # Reason 0x13 is remote user terminated connection.
    event = parse_event([0x04, 0x05, 0x04, 0x00, 0x40, 0x00, 0x13])
    assert isinstance(event, DisconnectionComplete)
    assert event.handle == 0x0040
    assert event.reason == 0x13


def test_encryption_change_reports_enabled_state():
    event = parse_event([0x04, 0x08, 0x04, 0x00, 0x40, 0x00, 0x01])
    assert isinstance(event, EncryptionChange)
    assert event.handle == 0x0040
    assert event.enabled == 0x01


def test_long_term_key_request_is_decoded():
    packet = [0x04, 0x3E, 0x0D, 0x05, 0x40, 0x00] \
        + [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] \
        + [0x34, 0x12]
    event = parse_event(packet)
    assert isinstance(event, LongTermKeyRequest)
    assert event.handle == 0x0040
    assert event.random_number == bytes(range(1, 9))
    assert event.encrypted_diversifier == 0x1234


def test_number_of_completed_packets_reports_every_handle():
    # Two handles: 0x0040 released 3 buffers, 0x0041 released 1.
    packet = [0x04, 0x13, 0x09, 0x02,
              0x40, 0x00, 0x03, 0x00,
              0x41, 0x00, 0x01, 0x00]
    event = parse_event(packet)
    assert isinstance(event, NumberOfCompletedPackets)
    assert event.counts == [(0x0040, 3), (0x0041, 1)]


def test_unhandled_events_are_ignored():
    # LE Advertising Report is not something a peripheral acts on.
    assert parse_event([0x04, 0x3E, 0x02, 0x02, 0x00]) is None


def test_address_formatting_reverses_octet_order():
    assert format_address([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA]) == "AA:BB:CC:DD:EE:FF"
