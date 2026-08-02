import sys
import time

from blekeyboard.keyboard import Keyboard

DEMO_TEXT = "hello from blekeyboard"


def main():
    print("Starting blekeyboard emulator service...")
    keyboard = Keyboard(log=print)

    try:
        print("Waiting for a host to pair and subscribe to notifications...")
        keyboard.connect()

        print(f"Host is ready. Get a text field focused, then press Enter to type {DEMO_TEXT!r}.")
        input()

        keyboard.type(DEMO_TEXT + "\n")

        print("Done. Press Ctrl+C to stop advertising.")
        while True:
            time.sleep(1.0)

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
