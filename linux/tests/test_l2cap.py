import pytest

from blekeyboard.hci import (
    ACL_PB_CONTINUING,
    ACL_PB_FIRST,
    ACLData,
    build_acl,
    fragment_payload,
    parse_acl,
    parse_le_buffer_size,
)
from blekeyboard.l2cap import (
    CID_ATT,
    CID_SMP,
    L2CAPReassembler,
    build_frame,
)


def att_frame(payload: bytes) -> bytes:
    return build_frame(CID_ATT, payload)


class TestACLFraming:
    def test_handle_and_boundary_share_one_field(self):
        packet = build_acl(0x0040, ACL_PB_FIRST, b"\x01\x02")
        parsed = parse_acl(packet)
        assert isinstance(parsed, ACLData)
        assert parsed.handle == 0x0040
        assert parsed.packet_boundary == ACL_PB_FIRST
        assert parsed.data == b"\x01\x02"

    def test_continuation_flag_survives_a_round_trip(self):
        parsed = parse_acl(build_acl(0x0EFF, ACL_PB_CONTINUING, b"\xAA"))
        assert parsed.handle == 0x0EFF
        assert parsed.packet_boundary == ACL_PB_CONTINUING

    def test_handle_is_masked_to_twelve_bits(self):
        # The upper nibble carries flags, so it must not leak into the handle.
        parsed = parse_acl(build_acl(0x0FFF, ACL_PB_FIRST, b""))
        assert parsed.handle == 0x0FFF

    def test_event_packets_are_not_acl_data(self):
        assert parse_acl([0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00]) is None

    def test_truncated_payload_is_rejected(self):
        # Declares four payload bytes but carries two.
        assert parse_acl([0x02, 0x40, 0x00, 0x04, 0x00, 0xAA, 0xBB]) is None


class TestFragmentation:
    def test_short_payload_is_a_single_first_fragment(self):
        assert fragment_payload(b"abc", 27) == [(ACL_PB_FIRST, b"abc")]

    def test_long_payload_continues_after_the_first_fragment(self):
        fragments = fragment_payload(b"abcdefg", 3)
        assert fragments == [
            (ACL_PB_FIRST, b"abc"),
            (ACL_PB_CONTINUING, b"def"),
            (ACL_PB_CONTINUING, b"g"),
        ]

    def test_payload_matching_the_limit_exactly_is_not_split(self):
        assert fragment_payload(b"abc", 3) == [(ACL_PB_FIRST, b"abc")]

    def test_empty_payload_still_produces_one_fragment(self):
        assert fragment_payload(b"", 27) == [(ACL_PB_FIRST, b"")]

    def test_zero_fragment_size_is_rejected(self):
        with pytest.raises(ValueError):
            fragment_payload(b"abc", 0)


class TestReassembly:
    def test_whole_frame_in_one_fragment(self):
        frames = L2CAPReassembler().feed(ACL_PB_FIRST, att_frame(b"\x01\x02\x03"))
        assert len(frames) == 1
        assert frames[0].cid == CID_ATT
        assert frames[0].payload == b"\x01\x02\x03"

    def test_frame_split_across_fragments_yields_nothing_until_complete(self):
        reassembler = L2CAPReassembler()
        data = att_frame(b"HELLO")

        assert reassembler.feed(ACL_PB_FIRST, data[:3]) == []
        assert reassembler.pending_bytes == 3

        frames = reassembler.feed(ACL_PB_CONTINUING, data[3:])
        assert len(frames) == 1
        assert frames[0].payload == b"HELLO"
        assert reassembler.pending_bytes == 0

    def test_frame_split_across_many_fragments(self):
        reassembler = L2CAPReassembler()
        data = att_frame(bytes(range(40)))

        collected = []
        for index in range(0, len(data), 7):
            boundary = ACL_PB_FIRST if index == 0 else ACL_PB_CONTINUING
            collected.extend(reassembler.feed(boundary, data[index:index + 7]))

        assert len(collected) == 1
        assert collected[0].payload == bytes(range(40))

    def test_two_frames_in_one_fragment_are_both_returned(self):
        combined = att_frame(b"\x01") + build_frame(CID_SMP, b"\x02\x03")
        frames = L2CAPReassembler().feed(ACL_PB_FIRST, combined)

        assert [f.cid for f in frames] == [CID_ATT, CID_SMP]
        assert [f.payload for f in frames] == [b"\x01", b"\x02\x03"]

    def test_a_new_start_fragment_discards_an_incomplete_frame(self):
        # A partial frame can never be completed once the peer starts a new
        # payload, and keeping it would corrupt everything that follows.
        reassembler = L2CAPReassembler()
        reassembler.feed(ACL_PB_FIRST, att_frame(b"DISCARDED")[:4])

        frames = reassembler.feed(ACL_PB_FIRST, att_frame(b"\x09"))
        assert len(frames) == 1
        assert frames[0].payload == b"\x09"

    def test_zero_length_payload_is_a_valid_frame(self):
        frames = L2CAPReassembler().feed(ACL_PB_FIRST, att_frame(b""))
        assert len(frames) == 1
        assert frames[0].payload == b""

    def test_reset_clears_buffered_data(self):
        reassembler = L2CAPReassembler()
        reassembler.feed(ACL_PB_FIRST, att_frame(b"PARTIAL")[:5])
        reassembler.reset()
        assert reassembler.pending_bytes == 0

    def test_channel_names_are_reported_for_known_channels(self):
        frames = L2CAPReassembler().feed(ACL_PB_FIRST, att_frame(b"\x01"))
        assert frames[0].channel_name == "ATT"

    def test_unknown_channel_falls_back_to_its_identifier(self):
        frames = L2CAPReassembler().feed(ACL_PB_FIRST, build_frame(0x0040, b"\x01"))
        assert frames[0].channel_name == "CID 0x0040"


class TestBufferSizeResponse:
    def test_capacity_is_read_from_a_successful_response(self):
        # Status 0, 251 byte payload, 12 buffers.
        assert parse_le_buffer_size(bytes([0x00, 0xFB, 0x00, 0x0C])) == (251, 12)

    def test_failure_status_reports_no_capacity(self):
        assert parse_le_buffer_size(bytes([0x01, 0xFB, 0x00, 0x0C])) is None

    def test_truncated_response_reports_no_capacity(self):
        assert parse_le_buffer_size(bytes([0x00, 0xFB])) is None

    def test_zero_length_signals_shared_bredr_buffers(self):
        # The caller must fall back to the legacy Read Buffer Size command.
        assert parse_le_buffer_size(bytes([0x00, 0x00, 0x00, 0x00])) == (0, 0)
