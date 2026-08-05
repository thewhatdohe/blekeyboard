"""
Best-effort identification of the host at the other end of the connection.

BLE has no field where a central announces its operating system - nothing in
the protocol requires it, and no host does it voluntarily. Everything here is
inferred from a handful of observable signals (the Pairing Request's
io_capability/auth_req, the requested ATT MTU, and the peer's address type),
cross-referenced against documented per-platform tendencies. Every one of
these signals can vary within the same physical device: this project has
directly observed the same iPhone requesting a different auth_req depending
on which iOS flow triggered pairing, and an MTU that flatly contradicted the
commonly cited iOS default. Treat every guess here as a hint for a pentester
choosing which payload to try, never as ground truth to branch protocol
behavior on - the SMP/GATT layers already adapt correctly to whatever a peer
actually declares, without needing to know its OS in advance.

Windows, Linux and macOS are not yet distinguishable from each other by any
signal this project has real evidence for; they are reported as "desktop,
unknown which" rather than guessed at random. Only iOS has a signal this
project has directly and repeatedly observed; Android's bucket exists but is
not yet backed by a real Android device.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class HostOS(Enum):
    IOS = auto()
    ANDROID = auto()
    WINDOWS = auto()
    MACOS = auto()
    LINUX = auto()
    UNKNOWN = auto()


@dataclass
class HostSignals:
    """Raw, observable values gathered from one connection's pairing exchange."""
    peer_address_type: Optional[int] = None    # 0x00 public, 0x01 random
    io_capability: Optional[int] = None
    auth_req: Optional[int] = None
    client_mtu: Optional[int] = None


@dataclass
class HostGuess:
    os: HostOS
    confidence: str  # "none", "low", or "medium" - never higher; see module docstring
    reasons: list = field(default_factory=list)


# Address type values from LE Connection Complete / LE Set Advertising
# Parameters: 0x00 is a public (fixed, factory) address, 0x01 a random one.
ADDRESS_TYPE_PUBLIC = 0x00
ADDRESS_TYPE_RANDOM = 0x01

# auth_req bits (see smp.py). Bit 3 is Secure Connections; bit 5 is CT2,
# the Core 5.2 cross-transport key derivation flag - a combination this
# project has only ever observed requested by iOS, never by anything else,
# though the sample size is exactly one phone.
_AUTH_REQ_SC = 0x08
_AUTH_REQ_CT2 = 0x20


def guess_host_os(signals: HostSignals) -> HostGuess:
    """
    A best-effort guess at the connected host's OS from what pairing reveals.

    See the module docstring for why this can never be more than a hint, and
    why Windows/Linux/macOS all currently resolve to UNKNOWN rather than a
    guess this project has no evidence to back.
    """
    reasons = []

    if signals.peer_address_type is None:
        return HostGuess(HostOS.UNKNOWN, "none", ["no connection observed yet"])

    if signals.peer_address_type == ADDRESS_TYPE_PUBLIC:
        reasons.append(
            "connected from a public Bluetooth address, typical of a desktop "
            "adapter rather than a phone's rotating privacy address"
        )
        reasons.append(
            "no signal this project has evidence for distinguishes Windows, "
            "Linux and macOS from each other yet"
        )
        return HostGuess(HostOS.UNKNOWN, "low", reasons)

    reasons.append("connected from a random (privacy) address, typical of a phone")

    if signals.auth_req is not None \
            and signals.auth_req & _AUTH_REQ_SC \
            and signals.auth_req & _AUTH_REQ_CT2:
        reasons.append(
            "requested Secure Connections with the CT2 cross-transport key "
            "derivation flag set - a combination this project has only "
            "observed from iOS"
        )
        return HostGuess(HostOS.IOS, "medium", reasons)

    reasons.append(
        "a random address without the iOS-associated CT2 pairing flag; "
        "consistent with Android, but untested against a real one"
    )
    return HostGuess(HostOS.ANDROID, "low", reasons)
