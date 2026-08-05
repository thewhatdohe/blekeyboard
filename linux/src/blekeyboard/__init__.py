from blekeyboard.duckyscript import DuckyScriptError
from blekeyboard.duckyscript import run as run_duckyscript
from blekeyboard.duckyscript import run_file as run_duckyscript_file
from blekeyboard.hostprofile import HostGuess, HostOS
from blekeyboard.keyboard import Keyboard

__all__ = [
    "Keyboard",
    "run_duckyscript",
    "run_duckyscript_file",
    "DuckyScriptError",
    "HostGuess",
    "HostOS",
]
