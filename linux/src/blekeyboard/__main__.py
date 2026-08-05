import sys

from blekeyboard.duckyscript import DuckyScriptError, run_file as run_duckyscript_file
from blekeyboard.keyboard import Keyboard

DEMO_TEXT = "hello from blekeyboard"

MENU = """\
Commands (focus a text field on the host first):
  [Enter]     type the demo text
  t <text>    type your own text
  run <path>  run a Ducky Script file (strings/keys/delays only, no combos)
  who         show the best-effort guess at the connected host's OS
  l           switch the host's input language (iOS: sends Ctrl+Space)
  r           release all keys (clears a stuck key/modifier on the host)
  ?           show this menu
  q           quit
"""


def _print_host_guess(keyboard):
    guess = keyboard.host_guess
    if guess is None:
        print("No connection yet.")
        return
    print(f"Best guess: {guess.os.name} (confidence: {guess.confidence})")
    for reason in guess.reasons:
        print(f"  - {reason}")


def _run_command(keyboard, command):
    """Runs one interactive command. Returns False to quit, True to continue."""
    if command in ("q", "quit"):
        return False

    if command in ("", None):
        keyboard.type(DEMO_TEXT)
    elif command in ("?", "help"):
        print(MENU)
    elif command == "who":
        _print_host_guess(keyboard)
    elif command == "l":
        keyboard.switch_input_language()
        print("Sent the language-switch shortcut (Ctrl+Space).")
    elif command == "r":
        keyboard.release_all()
        print("Released all keys.")
    elif command.startswith("t "):
        keyboard.type(command[2:])
    elif command.startswith("run "):
        try:
            run_duckyscript_file(keyboard, command[4:].strip())
        except (DuckyScriptError, OSError) as error:
            print(f"Script stopped: {error}")
    else:
        print(f"Unknown command {command!r}.")
        print(MENU)
    return True


def main():
    print("Starting blekeyboard emulator service...")
    keyboard = Keyboard(log=print)

    try:
        print("Waiting for a host to pair and subscribe to notifications...")
        keyboard.connect()
        print("Host is ready.")
        _print_host_guess(keyboard)

        # Clear anything the host may still believe is held from an earlier
        # run, so this session starts from a clean all-keys-up state.
        keyboard.release_all()

        print(MENU)
        while True:
            try:
                command = input("blekeyboard> ").strip()
            except EOFError:
                break

            try:
                if not _run_command(keyboard, command):
                    break
            except RuntimeError as error:
                # A dropped connection surfaces here; the background thread may
                # still be reconnecting, so report it and keep the prompt open.
                print(f"Not sent: {error}")

        return 0

    except KeyboardInterrupt:
        print("\nShutting down...")
        return 0
    except Exception as e:
        print(f"\nFatal error: {e}")
        return 1
    finally:
        keyboard.disconnect()
        print("Hardware interfaces released.")


if __name__ == "__main__":
    sys.exit(main())
