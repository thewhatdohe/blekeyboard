"""
L2CAP framing over the ACL data path.

An L2CAP frame is a two octet payload length, a two octet channel
identifier, and the payload. A frame may be split across several ACL
fragments, and a single ACL fragment may carry more than one frame, so
inbound data is buffered per connection until whole frames can be lifted
out of it.
"""

from dataclasses import dataclass

from blekeyboard.hci import ACL_PB_CONTINUING, ACL_PB_FIRST

# Fixed channel identifiers used on an LE link.
CID_ATT = 0x0004
CID_LE_SIGNALING = 0x0005
CID_SMP = 0x0006

CHANNEL_NAMES = {
    CID_ATT: "ATT",
    CID_LE_SIGNALING: "LE signalling",
    CID_SMP: "SMP",
}

# Length of the frame header preceding the payload.
HEADER_SIZE = 4


@dataclass
class L2CAPFrame:
    cid: int
    payload: bytes

    @property
    def channel_name(self) -> str:
        return CHANNEL_NAMES.get(self.cid, f"CID 0x{self.cid:04X}")


def build_frame(cid: int, payload: bytes) -> bytes:
    """Wraps a payload in an L2CAP header for the given channel."""
    return len(payload).to_bytes(2, "little") + cid.to_bytes(2, "little") + bytes(payload)


class L2CAPReassembler:
    """
    Rebuilds L2CAP frames from the ACL fragments of a single connection.

    One instance belongs to one connection handle, since fragments of
    different connections interleave freely on the transport.
    """

    def __init__(self):
        self._pending = bytearray()

    def feed(self, packet_boundary: int, fragment: bytes) -> list[L2CAPFrame]:
        """
        Adds one ACL fragment and returns whatever frames are now complete.

        A fragment flagged as the start of a payload discards any partial
        frame still buffered, because that earlier frame can no longer be
        completed and keeping it would corrupt everything after it.
        """
        if packet_boundary == ACL_PB_CONTINUING:
            self._pending.extend(fragment)
        else:
            self._pending = bytearray(fragment)

        frames = []
        while len(self._pending) >= HEADER_SIZE:
            length = int.from_bytes(self._pending[0:2], "little")
            total = HEADER_SIZE + length

            # Wait for the rest of the frame before lifting it out.
            if len(self._pending) < total:
                break

            cid = int.from_bytes(self._pending[2:4], "little")
            frames.append(L2CAPFrame(cid=cid, payload=bytes(self._pending[HEADER_SIZE:total])))
            del self._pending[:total]

        return frames

    @property
    def pending_bytes(self) -> int:
        """Number of buffered bytes not yet forming a complete frame."""
        return len(self._pending)

    def reset(self):
        """Discards buffered data, for use when a connection ends."""
        self._pending.clear()


__all__ = [
    "ACL_PB_CONTINUING",
    "ACL_PB_FIRST",
    "CID_ATT",
    "CID_LE_SIGNALING",
    "CID_SMP",
    "HEADER_SIZE",
    "L2CAPFrame",
    "L2CAPReassembler",
    "build_frame",
]
