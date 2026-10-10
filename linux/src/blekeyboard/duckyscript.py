"""
A restricted Ducky Script interpreter: strings, single named keys, and
delays only.

Full Ducky Script also has key combinations (GUI r, CTRL ALT DEL) and
HOLD/RELEASE for a key spanning multiple lines. Both are deliberately
unsupported here for now - not because Keyboard.press()/release() can't do
combinations, they already can, but because this restricted interpreter is
scoped to plain keystrokes only until combination syntax is designed. A line
naming one of those commands raises DuckyScriptError rather than being
silently misinterpreted or dropped.

    from blekeyboard import Keyboard, run_duckyscript

    keyboard = Keyboard()
    keyboard.connect()
    run_duckyscript(keyboard, '''
        REM opens Notes and types a line
        STRINGLN hello from blekeyboard
        DELAY 500
        STRING done
    ''')
"""

import time

from blekeyboard import keycodes as kc


class DuckyScriptError(ValueError):
    """A line could not be parsed, or names an unsupported command."""


_NAMED_KEYS = {
    "ENTER": kc.KEY_ENTER,
    "RETURN": kc.KEY_ENTER,
    "TAB": kc.KEY_TAB,
    "SPACE": kc.KEY_SPACE,
    "SPACEBAR": kc.KEY_SPACE,
    "ESCAPE": kc.KEY_ESCAPE,
    "ESC": kc.KEY_ESCAPE,
    "BACKSPACE": kc.KEY_BACKSPACE,
    "DELETE": kc.KEY_DELETE,
    "DEL": kc.KEY_DELETE,
    "HOME": kc.KEY_HOME,
    "END": kc.KEY_END,
    "INSERT": kc.KEY_INSERT,
    "PAGEUP": kc.KEY_PAGE_UP,
    "PAGEDOWN": kc.KEY_PAGE_DOWN,
    "UP": kc.KEY_UP_ARROW,
    "UPARROW": kc.KEY_UP_ARROW,
    "DOWN": kc.KEY_DOWN_ARROW,
    "DOWNARROW": kc.KEY_DOWN_ARROW,
    "LEFT": kc.KEY_LEFT_ARROW,
    "LEFTARROW": kc.KEY_LEFT_ARROW,
    "RIGHT": kc.KEY_RIGHT_ARROW,
    "RIGHTARROW": kc.KEY_RIGHT_ARROW,
    "CAPSLOCK": kc.KEY_CAPS_LOCK,
    "PRINTSCREEN": kc.KEY_PRINT_SCREEN,
    "SCROLLLOCK": kc.KEY_SCROLL_LOCK,
    "PAUSE": kc.KEY_PAUSE,
    "BREAK": kc.KEY_PAUSE,
}
# F1-F12 are contiguous from KEY_F1, per keycodes.py.
_NAMED_KEYS.update({f"F{n}": kc.KEY_F1 + (n - 1) for n in range(1, 13)})

# Recognized but deliberately unsupported for now - real Ducky Script uses
# these for modifier combinations or a key held across lines. Naming them
# here gets a script that uses one a specific, clear error instead of an
# "unknown command" or, worse, silently typing something else.
_UNSUPPORTED = frozenset({
    "GUI", "WINDOWS", "COMMAND", "CTRL", "CONTROL", "ALT", "OPTION", "SHIFT",
    "HOLD", "RELEASE", "REPEAT", "MOD", "MENU", "APP",
})


def run(keyboard, script: str, line_delay: float = 0.0):
    """
    Runs a restricted Ducky Script against a connected `Keyboard`.

    Supported commands, one per line: STRING/STRINGLN <text>, DELAY
    <milliseconds>, REM <comment>, and any of the single named keys in
    `_NAMED_KEYS` (ENTER, TAB, an arrow, F1-F12, ...) on their own.

    `line_delay` is an extra pause after every command, in seconds - useful
    against a host that drops reports sent back to back; DELAY lines add to
    it rather than replacing it.

    Raises DuckyScriptError, naming the line number, on a malformed or
    unsupported line. Nothing from before that line is undone.
    """
    for line_number, raw_line in enumerate(script.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        try:
            _run_line(keyboard, line)
        except DuckyScriptError as error:
            raise DuckyScriptError(f"Line {line_number}: {error}") from None

        if line_delay:
            time.sleep(line_delay)


def run_file(keyboard, path, line_delay: float = 0.0):
    """Reads a script from `path` and runs it; see `run`."""
    with open(path, "r", encoding="utf-8") as handle:
        run(keyboard, handle.read(), line_delay=line_delay)


def _run_line(keyboard, line: str):
    command, _, rest = line.partition(" ")
    command = command.upper()

    if command == "REM":
        return

    if command in ("STRING", "STRINGLN"):
        text = rest if command == "STRING" else rest + "\n"
        keyboard.type(text)
        return

    if command == "DELAY":
        _run_delay(rest)
        return

    if command in _NAMED_KEYS:
        if rest:
            raise DuckyScriptError(f"{command} takes no argument, got {rest!r}.")
        keyboard.tap(_NAMED_KEYS[command])
        return

    if command in _UNSUPPORTED:
        raise DuckyScriptError(
            f"{command!r} needs a key combination or a key held across lines, "
            f"which this interpreter does not support yet - only plain "
            f"keystrokes are."
        )

    raise DuckyScriptError(f"Unknown command {command!r}.")


def _run_delay(argument: str):
    try:
        milliseconds = int(argument)
    except ValueError:
        raise DuckyScriptError(
            f"DELAY needs a whole number of milliseconds, got {argument!r}."
        ) from None
    if milliseconds < 0:
        raise DuckyScriptError("DELAY cannot be negative.")
    time.sleep(milliseconds / 1000)
