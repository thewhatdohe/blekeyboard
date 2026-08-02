import pytest

from blekeyboard.hid_report_map import (
    INPUT_REPORT_LENGTH,
    KEYBOARD_REPORT_ID,
    MAX_SIMULTANEOUS_KEYS,
    REPORT_MAP,
    build_input_report,
)

# Item tags this test walks the descriptor for.
_COLLECTION = 0xA1
_END_COLLECTION = 0xC0
_REPORT_ID = 0x85


def test_collections_are_balanced():
    depth = 0
    i = 0
    while i < len(REPORT_MAP):
        tag = REPORT_MAP[i]
        size = {0: 0, 1: 1, 2: 2, 3: 4}[tag & 0x03]
        if tag == _COLLECTION:
            depth += 1
        elif tag == _END_COLLECTION:
            depth -= 1
        i += 1 + size
    assert depth == 0
    assert i == len(REPORT_MAP)


def test_report_id_matches_the_constant():
    index = REPORT_MAP.index(_REPORT_ID)
    assert REPORT_MAP[index + 1] == KEYBOARD_REPORT_ID


def test_input_report_length_accounts_for_the_report_id_byte():
    # Report ID + modifier + reserved + six keycodes.
    assert INPUT_REPORT_LENGTH == 1 + 1 + 1 + 6


def test_descriptor_is_well_formed_bytes():
    assert isinstance(REPORT_MAP, bytes)
    assert len(REPORT_MAP) > 0


class TestBuildInputReport:
    def test_report_starts_with_the_id_and_modifier(self):
        report = build_input_report(modifier=0x02, keycodes=[0x04])
        assert report[0] == KEYBOARD_REPORT_ID
        assert report[1] == 0x02

    def test_reserved_byte_is_always_zero(self):
        assert build_input_report(modifier=0xFF, keycodes=[0x04])[2] == 0x00

    def test_report_length_matches_the_wire_constant(self):
        assert len(build_input_report()) == INPUT_REPORT_LENGTH

    def test_empty_keycodes_is_the_all_zero_release_report(self):
        assert build_input_report() == bytes([KEYBOARD_REPORT_ID, 0, 0, 0, 0, 0, 0, 0, 0])

    def test_keycodes_are_left_packed_and_padded_with_zero(self):
        report = build_input_report(keycodes=[0x04, 0x05])
        assert report[3:5] == bytes([0x04, 0x05])
        assert report[5:] == bytes(4)

    def test_maximum_simultaneous_keys_fills_the_array_exactly(self):
        report = build_input_report(keycodes=[1, 2, 3, 4, 5, 6])
        assert report[3:] == bytes([1, 2, 3, 4, 5, 6])

    def test_more_than_six_keys_is_rejected(self):
        with pytest.raises(ValueError):
            build_input_report(keycodes=[1, 2, 3, 4, 5, 6, 7])

    def test_default_modifier_is_none_pressed(self):
        assert build_input_report(keycodes=[0x04])[1] == 0x00
