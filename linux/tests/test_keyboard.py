import pytest

from blekeyboard import keycodes as kc
from blekeyboard.keyboard import Keyboard


class StubLink:
    """
    Stands in for `Link` so the key state machine can be tested without a
    background thread or real transport. Records every report sent.
    """

    def __init__(self, ready=True):
        self.reports = []
        self._ready = ready

    @property
    def is_ready(self):
        return self._ready

    def send_key_report(self, modifier, keycodes):
        if not self._ready:
            return False
        self.reports.append((modifier, tuple(keycodes)))
        return True


def make_keyboard(ready=True):
    keyboard = Keyboard()
    keyboard._link = StubLink(ready=ready)
    return keyboard


class TestPress:
    def test_pressing_a_letter_sends_its_keycode(self):
        keyboard = make_keyboard()
        keyboard.press("a")
        assert keyboard._link.reports[-1] == (0, (kc.KEY_A,))

    def test_pressing_a_modifier_keycode_sets_the_modifier_byte_not_the_array(self):
        keyboard = make_keyboard()
        keyboard.press(Keyboard.KEY_GUI)
        assert keyboard._link.reports[-1] == (kc.MOD_LEFT_GUI, ())

    def test_combination_accumulates_across_calls(self):
        keyboard = make_keyboard()
        keyboard.press(Keyboard.KEY_GUI)
        keyboard.press("r")
        assert keyboard._link.reports[-1] == (kc.MOD_LEFT_GUI, (kc.keycode_for_char("r")[1],))

    def test_single_call_can_hold_a_modifier_and_a_key_together(self):
        keyboard = make_keyboard()
        keyboard.press(Keyboard.KEY_CTRL, Keyboard.KEY_ALT, "x")
        modifier, keycodes = keyboard._link.reports[-1]
        assert modifier == kc.MOD_LEFT_CTRL | kc.MOD_LEFT_ALT
        assert keycodes == (kc.keycode_for_char("x")[1],)

    def test_pressing_the_same_key_twice_does_not_duplicate_it(self):
        keyboard = make_keyboard()
        keyboard.press("a")
        keyboard.press("a")
        assert keyboard._link.reports[-1] == (0, (kc.KEY_A,))

    def test_a_seventh_simultaneous_key_is_rejected(self):
        keyboard = make_keyboard()
        keyboard.press("a", "b", "c", "d", "e", "f")
        with pytest.raises(ValueError):
            keyboard.press("g")

    def test_pressing_with_no_host_connected_raises(self):
        keyboard = make_keyboard(ready=False)
        with pytest.raises(RuntimeError):
            keyboard.press("a")


class TestRelease:
    def test_releasing_a_key_removes_it_from_the_report(self):
        keyboard = make_keyboard()
        keyboard.press("a", "b")
        keyboard.release("a")
        assert keyboard._link.reports[-1] == (0, (kc.keycode_for_char("b")[1],))

    def test_releasing_a_modifier_clears_its_bit(self):
        keyboard = make_keyboard()
        keyboard.press(Keyboard.KEY_GUI, "r")
        keyboard.release(Keyboard.KEY_GUI)
        assert keyboard._link.reports[-1] == (0, (kc.keycode_for_char("r")[1],))

    def test_releasing_a_key_that_was_not_held_is_a_no_op(self):
        keyboard = make_keyboard()
        keyboard.press("a")
        keyboard.release("z")
        assert keyboard._link.reports[-1] == (0, (kc.KEY_A,))

    def test_release_all_clears_everything(self):
        keyboard = make_keyboard()
        keyboard.press(Keyboard.KEY_CTRL, "a", "b")
        keyboard.release_all()
        assert keyboard._link.reports[-1] == (0, ())


class TestWrite:
    def test_write_sends_a_press_then_a_release_report(self):
        keyboard = make_keyboard()
        keyboard.write("a")
        assert keyboard._link.reports == [(0, (kc.KEY_A,)), (0, ())]

    def test_write_of_an_uppercase_letter_presses_shift_with_the_key(self):
        keyboard = make_keyboard()
        keyboard.write("A")
        assert keyboard._link.reports[0] == (kc.MOD_LEFT_SHIFT, (kc.KEY_A,))

    def test_write_of_an_uppercase_letter_lifts_the_key_before_shift(self):
        keyboard = make_keyboard()
        keyboard.write("A")
        reports = keyboard._link.reports

        # After the key, Shift is still held for one report, then released, so
        # the modifier and the key never clear in the same report.
        key_with_shift = reports.index((kc.MOD_LEFT_SHIFT, (kc.KEY_A,)))
        assert reports[key_with_shift + 1] == (kc.MOD_LEFT_SHIFT, ())
        assert reports[-1] == (0, ())

    def test_write_restores_previously_held_keys_afterwards(self):
        keyboard = make_keyboard()
        keyboard.press(Keyboard.KEY_CTRL)
        keyboard.write("a")
        # The release half of write() must put Ctrl back, not clear it.
        assert keyboard._link.reports[-1] == (kc.MOD_LEFT_CTRL, ())

    def test_multi_character_string_is_rejected(self):
        keyboard = make_keyboard()
        with pytest.raises(ValueError):
            keyboard.write("ab")

    def test_writing_with_no_host_connected_raises(self):
        keyboard = make_keyboard(ready=False)
        with pytest.raises(RuntimeError):
            keyboard.write("a")


class TestPrint:
    def test_print_writes_every_character_in_order(self):
        keyboard = make_keyboard()
        keyboard.print("hi")

        pressed = [report for report in keyboard._link.reports if report[1]]
        expected = [kc.keycode_for_char("h")[1], kc.keycode_for_char("i")[1]]
        assert [keycodes[0] for _mod, keycodes in pressed] == expected

    def test_type_is_an_alias_for_print(self):
        assert Keyboard.type is Keyboard.print

    def test_empty_string_sends_nothing(self):
        keyboard = make_keyboard()
        keyboard.print("")
        assert keyboard._link.reports == []


class TestTap:
    def test_tap_presses_the_combination_then_releases_everything(self):
        keyboard = make_keyboard()
        keyboard.tap(Keyboard.KEY_CTRL, " ")
        space = kc.keycode_for_char(" ")[1]
        assert keyboard._link.reports[0] == (kc.MOD_LEFT_CTRL, (space,))
        assert keyboard._link.reports[-1] == (0, ())

    def test_tap_sends_the_release_twice_so_a_dropped_one_cannot_strand_a_modifier(self):
        keyboard = make_keyboard()
        keyboard.tap(Keyboard.KEY_CTRL, " ")
        assert keyboard._link.reports.count((0, ())) >= 2

    def test_tap_lifts_ordinary_keys_before_modifiers(self):
        # The release must never change the modifier byte and the key array in
        # the same report; a real keyboard lifts the key while the modifier is
        # still held, then lifts the modifier. Doing both at once is what
        # strands a modifier on hosts like iOS.
        keyboard = make_keyboard()
        keyboard.tap(Keyboard.KEY_CTRL, "a")
        a = kc.keycode_for_char("a")[1]
        reports = keyboard._link.reports

        assert reports[0] == (kc.MOD_LEFT_CTRL, (a,))     # both down
        # 'a' up while Ctrl is still held, before any all-clear.
        key_up = reports.index((kc.MOD_LEFT_CTRL, ()))
        clean = next(i for i, r in enumerate(reports) if r == (0, ()))
        assert key_up < clean

    def test_switch_input_language_sends_ctrl_space(self):
        keyboard = make_keyboard()
        keyboard.switch_input_language()
        space = kc.keycode_for_char(" ")[1]
        assert keyboard._link.reports[0] == (kc.MOD_LEFT_CTRL, (space,))
        assert keyboard._link.reports[-1] == (0, ())


class TestReassertOnReady:
    def test_becoming_ready_sends_the_current_key_state(self):
        # The all-keys-up report on (re)connection is what clears a key the
        # host still thinks is held from before a drop.
        keyboard = make_keyboard(ready=True)
        was_ready = keyboard._reassert_on_ready(was_ready=False)
        assert was_ready is True
        assert keyboard._link.reports[-1] == (0, ())

    def test_staying_ready_does_not_resend(self):
        keyboard = make_keyboard(ready=True)
        keyboard._reassert_on_ready(was_ready=True)
        assert keyboard._link.reports == []

    def test_not_ready_sends_nothing_and_reports_not_ready(self):
        keyboard = make_keyboard(ready=False)
        assert keyboard._reassert_on_ready(was_ready=False) is False
        assert keyboard._link.reports == []

    def test_a_held_combination_is_reasserted_on_reconnect(self):
        keyboard = make_keyboard(ready=True)
        keyboard.press(Keyboard.KEY_GUI)
        keyboard._link.reports.clear()

        keyboard._reassert_on_ready(was_ready=False)
        assert keyboard._link.reports[-1] == (kc.MOD_LEFT_GUI, ())


class TestModifierAliases:
    def test_aliases_match_the_left_hand_keycodes(self):
        assert Keyboard.KEY_CTRL == kc.KEY_LEFT_CTRL
        assert Keyboard.KEY_SHIFT == kc.KEY_LEFT_SHIFT
        assert Keyboard.KEY_ALT == kc.KEY_LEFT_ALT
        assert Keyboard.KEY_GUI == kc.KEY_LEFT_GUI


class TestHostGuess:
    def test_none_before_any_connection_attempt(self):
        assert Keyboard(bond_store=None).host_guess is None


class TestIsConnected:
    def test_reflects_the_underlying_link(self):
        assert make_keyboard(ready=True).is_connected()
        assert not make_keyboard(ready=False).is_connected()

    def test_false_before_any_connection_attempt(self):
        assert not Keyboard().is_connected()
