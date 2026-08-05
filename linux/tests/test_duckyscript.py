import pytest

from blekeyboard import keycodes as kc
from blekeyboard.duckyscript import DuckyScriptError, run, run_file


class FakeKeyboard:
    """Records type()/tap() calls without touching any real link."""

    def __init__(self):
        self.calls = []

    def type(self, text):
        self.calls.append(("type", text))

    def tap(self, *keys):
        self.calls.append(("tap", keys))


class TestString:
    def test_string_types_the_rest_of_the_line_verbatim(self):
        keyboard = FakeKeyboard()
        run(keyboard, "STRING hello world")
        assert keyboard.calls == [("type", "hello world")]

    def test_stringln_appends_a_newline(self):
        keyboard = FakeKeyboard()
        run(keyboard, "STRINGLN hello")
        assert keyboard.calls == [("type", "hello\n")]

    def test_string_preserves_leading_and_internal_spacing(self):
        keyboard = FakeKeyboard()
        run(keyboard, "STRING   two  spaces")
        assert keyboard.calls == [("type", "  two  spaces")]

    def test_command_is_case_insensitive(self):
        keyboard = FakeKeyboard()
        run(keyboard, "string hi")
        assert keyboard.calls == [("type", "hi")]


class TestNamedKeys:
    def test_enter_taps_the_enter_key(self):
        keyboard = FakeKeyboard()
        run(keyboard, "ENTER")
        assert keyboard.calls == [("tap", (kc.KEY_ENTER,))]

    def test_arrow_and_function_keys_are_recognized(self):
        keyboard = FakeKeyboard()
        run(keyboard, "UP\nF5\nESC")
        assert keyboard.calls == [
            ("tap", (kc.KEY_UP_ARROW,)),
            ("tap", (kc.KEY_F1 + 4,)),
            ("tap", (kc.KEY_ESCAPE,)),
        ]

    def test_a_named_key_with_an_argument_is_rejected(self):
        keyboard = FakeKeyboard()
        with pytest.raises(DuckyScriptError):
            run(keyboard, "ENTER now")
        assert keyboard.calls == []


class TestDelay:
    def test_delay_pauses_and_sends_nothing(self):
        keyboard = FakeKeyboard()
        run(keyboard, "DELAY 1")
        assert keyboard.calls == []

    def test_negative_delay_is_rejected(self):
        with pytest.raises(DuckyScriptError):
            run(FakeKeyboard(), "DELAY -5")

    def test_non_numeric_delay_is_rejected(self):
        with pytest.raises(DuckyScriptError):
            run(FakeKeyboard(), "DELAY soon")


class TestComments:
    def test_rem_lines_are_ignored(self):
        keyboard = FakeKeyboard()
        run(keyboard, "REM this line does nothing\nSTRING hi")
        assert keyboard.calls == [("type", "hi")]

    def test_blank_lines_are_ignored(self):
        keyboard = FakeKeyboard()
        run(keyboard, "\n\nSTRING hi\n\n")
        assert keyboard.calls == [("type", "hi")]


class TestUnsupportedCommands:
    @pytest.mark.parametrize("line", [
        "GUI r", "CTRL ALT DEL", "SHIFT TAB", "ALT F4",
        "HOLD a", "RELEASE a", "REPEAT 3",
    ])
    def test_combinations_and_holds_are_rejected_with_a_clear_message(self, line):
        keyboard = FakeKeyboard()
        with pytest.raises(DuckyScriptError, match="combination|held"):
            run(keyboard, line)
        assert keyboard.calls == []

    def test_an_unknown_command_is_rejected(self):
        with pytest.raises(DuckyScriptError, match="Unknown command"):
            run(FakeKeyboard(), "FROBNICATE")


class TestErrorReporting:
    def test_error_names_the_line_number(self):
        keyboard = FakeKeyboard()
        script = "STRING first\nSTRING second\nBOGUS third"
        with pytest.raises(DuckyScriptError, match="Line 3"):
            run(keyboard, script)
        # Lines before the bad one still ran.
        assert keyboard.calls == [("type", "first"), ("type", "second")]


class TestFullScript:
    def test_a_realistic_script_runs_in_order(self):
        keyboard = FakeKeyboard()
        run(keyboard, """
            REM open a run dialog is out of scope (needs GUI), so just type
            STRINGLN notepad.exe
            DELAY 5
            STRING done
        """)
        assert keyboard.calls == [
            ("type", "notepad.exe\n"),
            ("type", "done"),
        ]


class TestRunFile:
    def test_run_file_reads_and_runs_a_script(self, tmp_path):
        path = tmp_path / "payload.txt"
        path.write_text("STRING from a file\n")

        keyboard = FakeKeyboard()
        run_file(keyboard, path)
        assert keyboard.calls == [("type", "from a file")]
