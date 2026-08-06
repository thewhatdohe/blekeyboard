"""
USB HID keyboard usage IDs, and the US layout mapping from characters to them.

These are the keycodes the Report Map's Keyboard/Keypad usage page refers to.
The character mapping assumes a host configured for a US keyboard layout,
which is what a HID keyboard implicitly commits to: the device sends
positions on a physical layout, not characters, and the host applies
whatever layout it has configured to interpret them.
"""

# Modifier bits, packed into the report's first byte.
MOD_LEFT_CTRL = 0x01
MOD_LEFT_SHIFT = 0x02
MOD_LEFT_ALT = 0x04
MOD_LEFT_GUI = 0x08
MOD_RIGHT_CTRL = 0x10
MOD_RIGHT_SHIFT = 0x20
MOD_RIGHT_ALT = 0x40
MOD_RIGHT_GUI = 0x80

# Letters, in order, occupy a contiguous run starting here.
KEY_A = 0x04
# Digits 1-9 are contiguous; 0 follows them rather than preceding them.
KEY_1 = 0x1E
KEY_0 = 0x27

KEY_ENTER = 0x28
KEY_ESCAPE = 0x29
KEY_BACKSPACE = 0x2A
KEY_TAB = 0x2B
KEY_SPACE = 0x2C
KEY_MINUS = 0x2D
KEY_EQUAL = 0x2E
KEY_LEFT_BRACKET = 0x2F
KEY_RIGHT_BRACKET = 0x30
KEY_BACKSLASH = 0x31
KEY_SEMICOLON = 0x33
KEY_QUOTE = 0x34
KEY_GRAVE = 0x35
KEY_COMMA = 0x36
KEY_PERIOD = 0x37
KEY_SLASH = 0x38
KEY_CAPS_LOCK = 0x39

KEY_F1 = 0x3A
KEY_F2 = 0x3B
KEY_F3 = 0x3C
KEY_F4 = 0x3D
KEY_F5 = 0x3E
KEY_F6 = 0x3F
KEY_F7 = 0x40
KEY_F8 = 0x41
KEY_F9 = 0x42
KEY_F10 = 0x43
KEY_F11 = 0x44
KEY_F12 = 0x45

KEY_PRINT_SCREEN = 0x46
KEY_SCROLL_LOCK = 0x47
KEY_PAUSE = 0x48
KEY_INSERT = 0x49
KEY_HOME = 0x4A
KEY_PAGE_UP = 0x4B
KEY_DELETE = 0x4C
KEY_END = 0x4D
KEY_PAGE_DOWN = 0x4E
KEY_RIGHT_ARROW = 0x4F
KEY_LEFT_ARROW = 0x50
KEY_DOWN_ARROW = 0x51
KEY_UP_ARROW = 0x52

KEY_LEFT_CTRL = 0xE0
KEY_LEFT_SHIFT = 0xE1
KEY_LEFT_ALT = 0xE2
KEY_LEFT_GUI = 0xE3
KEY_RIGHT_CTRL = 0xE4
KEY_RIGHT_SHIFT = 0xE5
KEY_RIGHT_ALT = 0xE6
KEY_RIGHT_GUI = 0xE7

# The modifier keycodes correspond one-to-one with the modifier bits, in the
# same order, which _MODIFIER_KEYCODES relies on below.
_MODIFIER_KEYCODES = {
    KEY_LEFT_CTRL: MOD_LEFT_CTRL,
    KEY_LEFT_SHIFT: MOD_LEFT_SHIFT,
    KEY_LEFT_ALT: MOD_LEFT_ALT,
    KEY_LEFT_GUI: MOD_LEFT_GUI,
    KEY_RIGHT_CTRL: MOD_RIGHT_CTRL,
    KEY_RIGHT_SHIFT: MOD_RIGHT_SHIFT,
    KEY_RIGHT_ALT: MOD_RIGHT_ALT,
    KEY_RIGHT_GUI: MOD_RIGHT_GUI,
}


def modifier_bit_for(keycode: int):
    """The modifier bit a modifier keycode corresponds to, or None."""
    return _MODIFIER_KEYCODES.get(keycode)


def _letters():
    return {chr(ord("a") + i): (0, KEY_A + i) for i in range(26)}


def _digits():
    # '1' through '9' are contiguous from KEY_1; '0' comes after them.
    mapping = {str(d): (0, KEY_1 + d - 1) for d in range(1, 10)}
    mapping["0"] = (0, KEY_0)
    return mapping


def _shifted_digit_row():
    # The row of symbols produced by holding Shift over the digit row.
    symbols = ")!@#$%^&*("
    return {
        symbols[i]: (MOD_LEFT_SHIFT, (KEY_1 + i - 1 if i > 0 else KEY_0))
        for i in range(10)
    }


# Characters with no shift requirement, keyed to (modifier, keycode).
_UNSHIFTED_PUNCTUATION = {
    "\n": (0, KEY_ENTER),
    "\t": (0, KEY_TAB),
    " ": (0, KEY_SPACE),
    "-": (0, KEY_MINUS),
    "=": (0, KEY_EQUAL),
    "[": (0, KEY_LEFT_BRACKET),
    "]": (0, KEY_RIGHT_BRACKET),
    "\\": (0, KEY_BACKSLASH),
    ";": (0, KEY_SEMICOLON),
    "'": (0, KEY_QUOTE),
    "`": (0, KEY_GRAVE),
    ",": (0, KEY_COMMA),
    ".": (0, KEY_PERIOD),
    "/": (0, KEY_SLASH),
}

# The shifted form of each of those, aligned by position on a US layout.
_SHIFTED_PUNCTUATION = {
    "_": (MOD_LEFT_SHIFT, KEY_MINUS),
    "+": (MOD_LEFT_SHIFT, KEY_EQUAL),
    "{": (MOD_LEFT_SHIFT, KEY_LEFT_BRACKET),
    "}": (MOD_LEFT_SHIFT, KEY_RIGHT_BRACKET),
    "|": (MOD_LEFT_SHIFT, KEY_BACKSLASH),
    ":": (MOD_LEFT_SHIFT, KEY_SEMICOLON),
    '"': (MOD_LEFT_SHIFT, KEY_QUOTE),
    "~": (MOD_LEFT_SHIFT, KEY_GRAVE),
    "<": (MOD_LEFT_SHIFT, KEY_COMMA),
    ">": (MOD_LEFT_SHIFT, KEY_PERIOD),
    "?": (MOD_LEFT_SHIFT, KEY_SLASH),
}


def _build_ascii_map():
    mapping = {}
    mapping.update(_letters())
    mapping.update({c.upper(): (MOD_LEFT_SHIFT, k) for c, (_, k) in _letters().items()})
    mapping.update(_digits())
    mapping.update(_shifted_digit_row())
    mapping.update(_UNSHIFTED_PUNCTUATION)
    mapping.update(_SHIFTED_PUNCTUATION)
    return mapping


# Maps a single ASCII character to (modifier_bits, keycode). Built once at
# import time; the helper functions above exist to keep each part of the US
# layout auditable rather than one large literal table.
ASCII_TO_KEYCODE = _build_ascii_map()


def keycode_for_char(char: str):
    """
    Looks up the (modifier_bits, keycode) pair for one character.

    Raises ValueError for a character with no representation on a HID
    keyboard, such as anything outside printable ASCII, rather than sending
    a report that silently types the wrong thing.
    """
    if char not in ASCII_TO_KEYCODE:
        raise ValueError(f"No HID keycode for character {char!r}.")
    return ASCII_TO_KEYCODE[char]
