import pytest

from blekeyboard.crypto import (
    BLOCK_SIZE,
    TK_JUST_WORKS,
    build_c1_p1,
    build_c1_p2,
    c1,
    s1,
    xor,
)

PREQ = bytes([0x01, 0x03, 0x00, 0x01, 0x10, 0x00, 0x00])
PRES = bytes([0x02, 0x03, 0x00, 0x01, 0x10, 0x00, 0x00])
INITIATOR_ADDRESS = bytes.fromhex("A1A2A3A4A5A6")
RESPONDER_ADDRESS = bytes.fromhex("B1B2B3B4B5B6")


class RecordingCipher:
    """Stands in for AES so the composition can be inspected."""

    def __init__(self):
        self.calls = []

    def __call__(self, key, block):
        self.calls.append((bytes(key), bytes(block)))
        # Deterministic and reversible, but not AES; only the structure of
        # the surrounding computation is under test here.
        return bytes((b + 1) & 0xFF for b in block)


def test_xor_combines_octet_by_octet():
    assert xor(b"\x0F\xF0", b"\xFF\x0F") == b"\xF0\xFF"


class TestConfirmInputs:
    def test_p1_orders_the_pairing_parameters(self):
        # Written pres || preq || rat || iat, so least significant first the
        # order reverses.
        p1 = build_c1_p1(PREQ, PRES, initiator_address_type=0x01,
                         responder_address_type=0x00)
        assert len(p1) == BLOCK_SIZE
        assert p1[0] == 0x01           # initiator address type
        assert p1[1] == 0x00           # responder address type
        assert p1[2:9] == PREQ
        assert p1[9:16] == PRES

    def test_p2_orders_the_addresses_with_trailing_padding(self):
        p2 = build_c1_p2(INITIATOR_ADDRESS, RESPONDER_ADDRESS)
        assert len(p2) == BLOCK_SIZE
        assert p2[0:6] == RESPONDER_ADDRESS
        assert p2[6:12] == INITIATOR_ADDRESS
        assert p2[12:16] == bytes(4)

    @pytest.mark.parametrize("preq,pres", [(b"\x01" * 6, PRES), (PREQ, b"\x02" * 8)])
    def test_wrong_length_pairing_pdus_are_rejected(self, preq, pres):
        with pytest.raises(ValueError):
            build_c1_p1(preq, pres, 0x00, 0x00)

    def test_wrong_length_addresses_are_rejected(self):
        with pytest.raises(ValueError):
            build_c1_p2(b"\x00" * 5, RESPONDER_ADDRESS)


class TestConfirmValue:
    def _run(self, cipher, rand=bytes(range(BLOCK_SIZE))):
        return c1(
            cipher, TK_JUST_WORKS, rand, PREQ, PRES,
            initiator_address_type=0x01, initiator_address=INITIATOR_ADDRESS,
            responder_address_type=0x00, responder_address=RESPONDER_ADDRESS,
        )

    def test_two_encryptions_are_performed(self):
        cipher = RecordingCipher()
        self._run(cipher)
        assert len(cipher.calls) == 2

    def test_first_block_is_the_nonce_mixed_with_p1(self):
        cipher = RecordingCipher()
        rand = bytes(range(BLOCK_SIZE))
        self._run(cipher, rand)

        p1 = build_c1_p1(PREQ, PRES, 0x01, 0x00)
        assert cipher.calls[0][1] == xor(rand, p1)

    def test_second_block_mixes_the_first_result_with_p2(self):
        cipher = RecordingCipher()
        self._run(cipher)

        first_result = bytes((b + 1) & 0xFF for b in cipher.calls[0][1])
        p2 = build_c1_p2(INITIATOR_ADDRESS, RESPONDER_ADDRESS)
        assert cipher.calls[1][1] == xor(first_result, p2)

    def test_both_encryptions_use_the_temporary_key(self):
        cipher = RecordingCipher()
        self._run(cipher)
        assert all(key == TK_JUST_WORKS for key, _ in cipher.calls)

    def test_result_is_a_full_block(self):
        assert len(self._run(RecordingCipher())) == BLOCK_SIZE

    def test_a_different_nonce_changes_the_confirm_value(self):
        first = self._run(RecordingCipher(), bytes(BLOCK_SIZE))
        second = self._run(RecordingCipher(), bytes([0xFF]) + bytes(BLOCK_SIZE - 1))
        assert first != second

    def test_wrong_length_nonce_is_rejected(self):
        with pytest.raises(ValueError):
            c1(RecordingCipher(), TK_JUST_WORKS, b"\x00" * 8, PREQ, PRES,
               0x00, INITIATOR_ADDRESS, 0x00, RESPONDER_ADDRESS)


class TestShortTermKey:
    def test_only_the_lower_half_of_each_nonce_contributes(self):
        cipher = RecordingCipher()
        responder = bytes(range(16))
        initiator = bytes(range(100, 116))

        s1(cipher, TK_JUST_WORKS, responder, initiator)

        block = cipher.calls[0][1]
        assert block[:8] == initiator[:8]
        assert block[8:] == responder[:8]

    def test_result_is_a_full_block(self):
        result = s1(RecordingCipher(), TK_JUST_WORKS, bytes(16), bytes(16))
        assert len(result) == BLOCK_SIZE

    def test_swapping_the_nonces_changes_the_key(self):
        a, b = bytes(range(16)), bytes(range(100, 116))
        assert s1(RecordingCipher(), TK_JUST_WORKS, a, b) != \
            s1(RecordingCipher(), TK_JUST_WORKS, b, a)

    def test_wrong_length_nonce_is_rejected(self):
        with pytest.raises(ValueError):
            s1(RecordingCipher(), TK_JUST_WORKS, b"\x00" * 8, bytes(16))


def test_just_works_temporary_key_is_all_zero():
    # Neither side contributes entropy in Just Works, which is precisely why
    # it offers no protection against a man in the middle.
    assert TK_JUST_WORKS == bytes(16)
