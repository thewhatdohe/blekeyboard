import pytest

from blekeyboard import keycodes as kc


class TestLetters:
    def test_lowercase_letters_are_unmodified(self):
        for offset, letter in enumerate("abcdefghijklmnopqrstuvwxyz"):
            modifier, keycode = kc.keycode_for_char(letter)
            assert modifier == 0
            assert keycode == kc.KEY_A + offset

    def test_uppercase_letters_require_shift(self):
        modifier, keycode = kc.keycode_for_char("A")
        assert modifier == kc.MOD_LEFT_SHIFT
        assert keycode == kc.KEY_A

    def test_uppercase_and_lowercase_share_a_keycode(self):
        assert kc.keycode_for_char("g")[1] == kc.keycode_for_char("G")[1]


class TestDigits:
    @pytest.mark.parametrize("digit,expected", [
        ("1", kc.KEY_1), ("9", kc.KEY_1 + 8), ("0", kc.KEY_0),
    ])
    def test_digit_keycodes(self, digit, expected):
        modifier, keycode = kc.keycode_for_char(digit)
        assert modifier == 0
        assert keycode == expected

    def test_digits_one_through_nine_are_contiguous(self):
        keycodes = [kc.keycode_for_char(str(d))[1] for d in range(1, 10)]
        assert keycodes == list(range(kc.KEY_1, kc.KEY_1 + 9))


class TestShiftedDigitRow:
    @pytest.mark.parametrize("symbol,digit", [
        ("!", "1"), ("@", "2"), ("#", "3"), ("$", "4"), ("%", "5"),
        ("^", "6"), ("&", "7"), ("*", "8"), ("(", "9"), (")", "0"),
    ])
    def test_shifted_symbol_shares_the_digit_keycode(self, symbol, digit):
        shifted_mod, shifted_key = kc.keycode_for_char(symbol)
        _, digit_key = kc.keycode_for_char(digit)
        assert shifted_mod == kc.MOD_LEFT_SHIFT
        assert shifted_key == digit_key


class TestPunctuation:
    def test_enter_maps_to_the_newline_character(self):
        assert kc.keycode_for_char("\n") == (0, kc.KEY_ENTER)

    def test_space_bar(self):
        assert kc.keycode_for_char(" ") == (0, kc.KEY_SPACE)

    @pytest.mark.parametrize("char,expected_key", [
        ("-", kc.KEY_MINUS), ("=", kc.KEY_EQUAL),
        ("[", kc.KEY_LEFT_BRACKET), ("]", kc.KEY_RIGHT_BRACKET),
        (";", kc.KEY_SEMICOLON), ("'", kc.KEY_QUOTE),
        (",", kc.KEY_COMMA), (".", kc.KEY_PERIOD), ("/", kc.KEY_SLASH),
    ])
    def test_unshifted_punctuation(self, char, expected_key):
        assert kc.keycode_for_char(char) == (0, expected_key)

    @pytest.mark.parametrize("char,base_char", [
        ("_", "-"), ("+", "="), ("{", "["), ("}", "]"),
        (":", ";"), ('"', "'"), ("<", ","), (">", "."), ("?", "/"),
    ])
    def test_shifted_punctuation_shares_the_unshifted_keycode(self, char, base_char):
        shifted_mod, shifted_key = kc.keycode_for_char(char)
        _, base_key = kc.keycode_for_char(base_char)
        assert shifted_mod == kc.MOD_LEFT_SHIFT
        assert shifted_key == base_key


class TestCoverage:
    def test_every_printable_ascii_character_is_mapped(self):
        missing = []
        for codepoint in range(32, 127):
            try:
                kc.keycode_for_char(chr(codepoint))
            except ValueError:
                missing.append(chr(codepoint))
        assert missing == []

    def test_unmapped_character_raises(self):
        with pytest.raises(ValueError):
            kc.keycode_for_char("\x01")

    def test_control_characters_other_than_tab_and_newline_are_rejected(self):
        with pytest.raises(ValueError):
            kc.keycode_for_char("\r")


class TestFunctionKeys:
    def test_f1_through_f12_are_contiguous_from_f1(self):
        for n in range(1, 13):
            assert getattr(kc, f"KEY_F{n}") == kc.KEY_F1 + (n - 1)

    def test_f12_does_not_collide_with_print_screen(self):
        assert kc.KEY_F12 < kc.KEY_PRINT_SCREEN


class TestModifierBits:
    def test_each_modifier_keycode_maps_to_its_bit(self):
        assert kc.modifier_bit_for(kc.KEY_LEFT_CTRL) == kc.MOD_LEFT_CTRL
        assert kc.modifier_bit_for(kc.KEY_RIGHT_GUI) == kc.MOD_RIGHT_GUI

    def test_non_modifier_keycode_has_no_bit(self):
        assert kc.modifier_bit_for(kc.KEY_A) is None
