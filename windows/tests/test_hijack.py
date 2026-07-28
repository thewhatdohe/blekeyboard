import pytest
from blekeyboard.emulator import BLEBroadcaster

def test_name_length_limit():
    broadcaster = BLEBroadcaster(transport=None)
    
    # A name longer than 26 bytes should instantly throw a ValueError
    with pytest.raises(ValueError):
        broadcaster.set_advertising_payload("ThisNameIsWayTooLongForABLESignedAdvertisingSlot")