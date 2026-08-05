import pytest

from blekeyboard.emulator import BLEBroadcaster


class RecordingTransport:
    """Captures the packets a broadcaster writes, in order."""

    def __init__(self):
        self.packets = []

    def send_control_packet(self, packet):
        self.packets.append(packet)

    @property
    def last(self):
        return self.packets[-1]


@pytest.fixture
def transport():
    return RecordingTransport()


@pytest.fixture
def broadcaster(transport):
    return BLEBroadcaster(transport)


def test_opcode_is_packed_little_endian_with_length(broadcaster, transport):
    # OCF 0x000A with OGF 0x08 encodes as opcode 0x200A, followed by the
    # parameter length and the parameter itself.
    broadcaster.set_state(enable=True)
    assert transport.last == [0x0A, 0x20, 0x01, 0x01]


def test_disabling_advertising_flips_only_the_state_byte(broadcaster, transport):
    broadcaster.set_state(enable=False)
    assert transport.last == [0x0A, 0x20, 0x01, 0x00]


def test_reset_uses_the_controller_baseband_group(broadcaster, transport):
    # HCI Reset is OCF 0x0003 under OGF 0x03, giving opcode 0x0C03.
    broadcaster.reset_controller()
    assert transport.last == [0x03, 0x0C, 0x00]


def test_event_mask_enables_le_meta_events(broadcaster, transport):
    # The controller default omits LE Meta Event (bit 61), which would leave
    # connection events undelivered, so the mask must set it.
    broadcaster.set_event_mask()
    opcode_low, opcode_high, length, *mask = transport.last
    assert (opcode_low, opcode_high) == (0x01, 0x0C)
    assert length == 8
    assert mask == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0x00, 0x20]

    value = int.from_bytes(bytes(mask), "little")
    assert value & (1 << 61)


def test_le_event_mask_covers_connection_and_key_request(broadcaster, transport):
    broadcaster.set_le_event_mask()
    opcode_low, opcode_high, length, *mask = transport.last
    assert (opcode_low, opcode_high) == (0x01, 0x20)
    assert length == 8

    value = int.from_bytes(bytes(mask), "little")
    assert value & (1 << 0)  # LE Connection Complete
    assert value & (1 << 4)  # LE Long Term Key Request
    assert value & (1 << 7)  # LE Read Local P-256 Public Key Complete
    assert value & (1 << 8)  # LE Generate DHKey Complete


def test_advertising_interval_is_converted_to_slots(broadcaster, transport):
    # 400ms divided by the 0.625ms slot unit is 640 slots, or 0x0280.
    broadcaster.configure_advertising(interval_ms=400)
    params = transport.last[3:]
    assert params[0:2] == [0x80, 0x02]
    assert params[2:4] == [0x80, 0x02]


def test_advertising_is_connectable_on_all_channels(broadcaster, transport):
    broadcaster.configure_advertising(interval_ms=400)
    params = transport.last[3:]

    # Fifteen parameters: two intervals, advertising type, two address types,
    # a six octet peer address, the channel map and the filter policy.
    assert len(params) == 15
    assert params[4] == 0x00  # ADV_IND, connectable and undirected
    assert params[7:13] == [0x00] * 6  # peer address, unused when broadcasting
    assert params[13] == 0x07  # channels 37, 38 and 39
    assert params[14] == 0x00  # accept scan and connect requests from anyone


@pytest.mark.parametrize("interval_ms", [10, 19, 10241, 20000])
def test_out_of_range_intervals_are_rejected(broadcaster, transport, interval_ms):
    with pytest.raises(ValueError):
        broadcaster.configure_advertising(interval_ms=interval_ms)
    assert transport.packets == []


@pytest.mark.parametrize("interval_ms", [20, 400, 10240])
def test_in_range_intervals_are_accepted(broadcaster, interval_ms):
    broadcaster.configure_advertising(interval_ms=interval_ms)


def test_advertising_payload_is_padded_to_the_full_slot(broadcaster, transport):
    broadcaster.set_advertising_payload("BLE-Ducky")
    params = transport.last[3:]

    # One length byte followed by exactly 31 bytes of advertising data.
    assert len(params) == 32

    # Flags: length 2, type 0x01, general discoverable with BR/EDR unsupported.
    assert params[1:4] == [0x02, 0x01, 0x06]

    # Complete Local Name, type 0x09, carrying the requested name.
    assert params[4] == len(b"BLE-Ducky") + 1
    assert params[5] == 0x09
    assert bytes(params[6:6 + 9]) == b"BLE-Ducky"

    # The declared length must match the data preceding the padding.
    assert params[0] == 3 + 2 + len(b"BLE-Ducky")
    assert set(params[1 + params[0]:]) == {0x00}


def test_overlong_device_name_is_rejected(broadcaster, transport):
    with pytest.raises(ValueError):
        broadcaster.set_advertising_payload("A" * 27)
    assert transport.packets == []


def test_keepalive_reads_local_version_information(broadcaster, transport):
    # OCF 0x0001 under the informational group gives opcode 0x1001.
    broadcaster.send_keepalive_ping()
    assert transport.last == [0x01, 0x10, 0x00]


def test_p256_public_key_request_takes_no_parameters(broadcaster, transport):
    # OCF 0x0025 under the LE group gives opcode 0x2025.
    broadcaster.le_read_local_p256_public_key()
    assert transport.last == [0x25, 0x20, 0x00]


def test_generate_dhkey_sends_the_remote_public_key(broadcaster, transport):
    # OCF 0x0026 under the LE group gives opcode 0x2026.
    remote_key = bytes(range(64))
    broadcaster.le_generate_dhkey(remote_key)
    assert transport.last == [0x26, 0x20, 0x40] + list(remote_key)


def test_generate_dhkey_rejects_a_malformed_public_key(broadcaster, transport):
    with pytest.raises(ValueError):
        broadcaster.le_generate_dhkey(bytes(63))
    assert transport.packets == []
