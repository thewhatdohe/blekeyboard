from blekeyboard.emulator import BLEBroadcaster

def test_hci_packet_building():
    # Setup a mock/dummy transport just to catch the bytes
    class MockTransport:
        def __init__(self): self.sent_packet = None
        def send_control_packet(self, packet): self.sent_packet = packet

    mock_transport = MockTransport()
    broadcaster = BLEBroadcaster(mock_transport)
    
    # Trigger a command
    broadcaster.set_state(enable=True)
    
    # Verify the packet header matches exactly what the Bluetooth Spec requires
    # OCF 0x000A, OGF 0x08 -> Opcode should compute to [0x0A, 0x20, 0x01, 0x01]
    assert mock_transport.sent_packet == [0x0A, 0x20, 0x01, 0x01]