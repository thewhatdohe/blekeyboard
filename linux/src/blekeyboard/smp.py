"""
Security Manager pairing, in the responder role.

Implements both LE Legacy and LE Secure Connections pairing, in each case
using the Just Works association model, which is what a keyboard with no
display and no input can offer. The result is an encrypted link, which HID
over GATT requires before a host will accept input.

Secure Connections is used whenever the peer requests it and this device has
been given the keypair callbacks it needs; only a peer that cannot do SC at
all falls back to Legacy. This is not a style preference: some hosts, iOS
included, complete Legacy Just Works pairing and encrypt the link without
error, but never actually route HID input to the foreground app unless the
bond was formed with genuine Secure Connections.

Just Works, in either form, provides no protection against a man in the
middle: the key exchange authenticates nothing about who is on the other
end, so an attacker positioned between the two devices during pairing can
complete it with both. It protects an already-paired session from passive
eavesdropping, nothing more.

After encryption succeeds, the responder key distribution phase hands the
peer a freshly generated Long Term Key tied to an EDIV/Rand pair. This is
not just a convenience for later reconnection: several BLE hosts, Android's
HID input framework included, gate whether a peripheral is treated as a
trusted input device on whether a real bond was formed, not merely on
whether the current session happens to be encrypted. Skipping this leaves a
peripheral that encrypts correctly and is nonetheless never actually treated
as a keyboard. This layer only forms the bond; persisting it across runs, so
a reconnecting host can resume without re-pairing, is `bonds.py`'s job.

All 128-bit values here stay least significant octet first, matching both the
wire format and the controller's encryption command.
"""

from dataclasses import dataclass
from enum import Enum, auto

from blekeyboard import crypto

# Command codes.
PAIRING_REQUEST = 0x01
PAIRING_RESPONSE = 0x02
PAIRING_CONFIRM = 0x03
PAIRING_RANDOM = 0x04
PAIRING_FAILED = 0x05
ENCRYPTION_INFORMATION = 0x06
MASTER_IDENTIFICATION = 0x07
IDENTITY_INFORMATION = 0x08
IDENTITY_ADDRESS_INFORMATION = 0x09
SIGNING_INFORMATION = 0x0A
SECURITY_REQUEST = 0x0B
PUBLIC_KEY = 0x0C
DHKEY_CHECK = 0x0D

# Reasons carried by Pairing Failed.
FAILED_OOB_NOT_AVAILABLE = 0x02
FAILED_AUTHENTICATION_REQUIREMENTS = 0x03
FAILED_CONFIRM_VALUE_FAILED = 0x04
FAILED_PAIRING_NOT_SUPPORTED = 0x05
FAILED_ENCRYPTION_KEY_SIZE = 0x06
FAILED_COMMAND_NOT_SUPPORTED = 0x07
FAILED_UNSPECIFIED_REASON = 0x08
FAILED_INVALID_PARAMETERS = 0x0A
FAILED_DHKEY_CHECK_FAILED = 0x0B

# A dummy `r` value for the DHKey Check: nonzero only for Passkey Entry and
# OOB association, neither of which this device offers.
_DHKEY_CHECK_R = bytes(16)

# Input and output capabilities. A keyboard peripheral has neither a display
# nor a way for the user to answer a prompt, so it can only offer Just Works.
IO_CAPABILITY_NO_INPUT_NO_OUTPUT = 0x03

# Authentication requirement bits.
AUTH_REQ_BONDING = 0x01
AUTH_REQ_MITM = 0x04
AUTH_REQ_SECURE_CONNECTIONS = 0x08

# Key distribution bits, carried in the last two octets of a pairing PDU.
KEY_DIST_ENC_KEY = 0x01
KEY_DIST_ID_KEY = 0x02
KEY_DIST_SIGN_KEY = 0x04

MAX_ENCRYPTION_KEY_SIZE = 16
MIN_ENCRYPTION_KEY_SIZE = 7

PAIRING_PDU_LENGTH = 7


class State(Enum):
    IDLE = auto()
    AWAITING_CONFIRM = auto()
    AWAITING_RANDOM = auto()
    AWAITING_PUBLIC_KEY = auto()
    AWAITING_SC_RANDOM = auto()
    AWAITING_DHKEY_CHECK = auto()
    AWAITING_ENCRYPTION = auto()
    ENCRYPTED = auto()
    FAILED = auto()


@dataclass
class PairingFeatures:
    io_capability: int
    oob_data_flag: int
    auth_req: int
    max_key_size: int
    initiator_key_distribution: int
    responder_key_distribution: int

    @classmethod
    def parse(cls, payload: bytes):
        if len(payload) < 6:
            return None
        return cls(
            io_capability=payload[0],
            oob_data_flag=payload[1],
            auth_req=payload[2],
            max_key_size=payload[3],
            initiator_key_distribution=payload[4],
            responder_key_distribution=payload[5],
        )

    def encode(self, code: int) -> bytes:
        return bytes([
            code,
            self.io_capability,
            self.oob_data_flag,
            self.auth_req,
            self.max_key_size,
            self.initiator_key_distribution,
            self.responder_key_distribution,
        ])


def pairing_failed(reason: int) -> bytes:
    return bytes([PAIRING_FAILED, reason])


def security_request(auth_req: int = 0x00) -> bytes:
    """
    Asks the connected peer to start pairing.

    A peripheral cannot initiate pairing itself; it can only state that it
    wants the link secured and leave the peer to begin the exchange.
    """
    return bytes([SECURITY_REQUEST, auth_req])


@dataclass
class BondKeys:
    """A Long Term Key and the EDIV/Rand pair a peer will present to reuse it."""
    ltk: bytes
    ediv: int
    rand: bytes

    def encode_pdus(self) -> tuple[bytes, bytes]:
        """
        The two SMP PDUs that hand this bond to the peer.

        Sent as a pair: Encryption Information carries the key itself, and
        Master Identification carries the EDIV/Rand the peer echoes back on
        a later LE Long Term Key Request to say which bond it wants resumed.
        """
        encryption_information = bytes([ENCRYPTION_INFORMATION]) + self.ltk
        master_identification = bytes([MASTER_IDENTIFICATION]) \
            + self.ediv.to_bytes(2, "little") + self.rand
        return encryption_information, master_identification

    def matches(self, encrypted_diversifier: int, random_number: bytes) -> bool:
        return encrypted_diversifier == self.ediv and bytes(random_number) == self.rand


class SecurityManager:
    """
    Drives one connection's pairing exchange.

    The caller feeds it inbound SMP payloads and forwards whatever it returns.
    When the peer starts encryption the controller asks for a key, which
    `long_term_key_for` supplies.
    """

    def __init__(self, encrypt, random_bytes, local_address: bytes,
                 local_address_type: int = 0x00,
                 generate_keypair=None, compute_dhkey=None):
        self._encrypt = encrypt
        self._random_bytes = random_bytes
        self._local_address = bytes(local_address)
        self._local_address_type = local_address_type
        # Both are None in tests that only exercise the legacy path, which
        # keeps Secure Connections off regardless of what the peer requests -
        # there is no keypair to offer it with.
        self._generate_keypair = generate_keypair
        self._compute_dhkey = compute_dhkey

        self.state = State.IDLE
        self.failure_reason = None

        self._peer_address = b""
        self._peer_address_type = 0x00
        self._preq = b""
        self._pres = b""
        self._peer_confirm = b""
        self._peer_random = b""
        self._own_random = b""
        self._short_term_key = None

        self._use_sc = False
        self._local_public_key = b""
        self._peer_public_key = b""
        self._dhkey = b""
        self._mackey = b""
        # PDUs a handler needed to send in addition to its own return value.
        # Only Secure Connections needs this: the responder answers a peer's
        # Public Key with both its own Public Key and its Pairing Confirm.
        self._queued_pdus = []

    def begin_connection(self, peer_address: bytes, peer_address_type: int):
        """Resets state for a newly connected peer."""
        self.__init__(self._encrypt, self._random_bytes,
                      self._local_address, self._local_address_type,
                      self._generate_keypair, self._compute_dhkey)
        self._peer_address = bytes(peer_address)
        self._peer_address_type = peer_address_type

    @property
    def short_term_key(self):
        return self._short_term_key

    @property
    def peer_features(self):
        """
        The peer's declared io_capability/auth_req/etc from its Pairing
        Request, or None before one has arrived. Exposed for host
        identification (see hostprofile.py); nothing in the pairing logic
        itself needs this after the exchange completes.
        """
        if not self._preq:
            return None
        return PairingFeatures.parse(self._preq[1:])

    @property
    def use_sc(self):
        return self._use_sc

    def drain_queued_pdus(self):
        """Returns and clears any extra PDUs a handler queued alongside its reply."""
        pdus = self._queued_pdus
        self._queued_pdus = []
        return pdus

    def handle_pdu(self, payload: bytes):
        """Processes one SMP payload, returning the reply to send or None."""
        if not payload:
            return None

        code = payload[0]
        body = payload[1:]

        if code == PAIRING_REQUEST:
            return self._handle_pairing_request(payload, body)
        if code == PAIRING_CONFIRM:
            return self._handle_pairing_confirm(body)
        if code == PAIRING_RANDOM:
            return self._handle_pairing_random(body)
        if code == PUBLIC_KEY:
            return self._handle_public_key(body)
        if code == DHKEY_CHECK:
            return self._handle_dhkey_check(body)
        if code == PAIRING_FAILED:
            self.state = State.FAILED
            self.failure_reason = body[0] if body else FAILED_UNSPECIFIED_REASON
            return None

        # Key distribution PDUs are accepted and ignored; nothing is stored
        # because this implementation does not bond.
        if code in (ENCRYPTION_INFORMATION, MASTER_IDENTIFICATION,
                    IDENTITY_INFORMATION, IDENTITY_ADDRESS_INFORMATION,
                    SIGNING_INFORMATION):
            return None

        return self._fail(FAILED_COMMAND_NOT_SUPPORTED)

    def _handle_pairing_request(self, whole_pdu: bytes, body: bytes):
        if len(whole_pdu) != PAIRING_PDU_LENGTH:
            return self._fail(FAILED_INVALID_PARAMETERS)

        features = PairingFeatures.parse(body)
        if features is None:
            return self._fail(FAILED_INVALID_PARAMETERS)

        if not MIN_ENCRYPTION_KEY_SIZE <= features.max_key_size <= MAX_ENCRYPTION_KEY_SIZE:
            return self._fail(FAILED_ENCRYPTION_KEY_SIZE)

        # Out of band data is the one thing that would change the key
        # derivation, and there is no channel to carry it.
        if features.oob_data_flag:
            return self._fail(FAILED_OOB_NOT_AVAILABLE)

        # A peer may ask for protection against a man in the middle, but that
        # is only ever a hope, not something it can force: per the IO
        # capability table, a device with no display and no input can only
        # ever offer Just Works, regardless of what either side's auth_req
        # requests. Refusing to pair over an unmet MITM request would be
        # this responder unilaterally declining something the peer only
        # asked for optimistically - pairing proceeds with Just Works
        # instead, which simply does not provide that protection.
        self._preq = bytes(whole_pdu)

        # A responder can only go along with Secure Connections if the peer
        # asked for it and this device actually has a keypair to offer one
        # with; a responder can never add SC on its own. Falling back to
        # Legacy here is what several hosts, iOS included, do NOT treat as a
        # real bond - Legacy is kept only for peers or environments that
        # cannot do SC at all.
        self._use_sc = bool(features.auth_req & AUTH_REQ_SECURE_CONNECTIONS) \
            and self._generate_keypair is not None

        if self._use_sc:
            # SC's own key exchange already produces a durable LTK, so no
            # separate EncKey/MasterID distribution phase is needed or
            # declared - see `Link._distribute_bond_keys`.
            response = PairingFeatures(
                io_capability=IO_CAPABILITY_NO_INPUT_NO_OUTPUT,
                oob_data_flag=0x00,
                auth_req=AUTH_REQ_BONDING | AUTH_REQ_SECURE_CONNECTIONS,
                max_key_size=MAX_ENCRYPTION_KEY_SIZE,
                initiator_key_distribution=0x00,
                responder_key_distribution=0x00,
            )
        else:
            # Nothing is requested from the peer, since a keyboard never
            # needs to read anything back from it, but this responder does
            # distribute its own EncKey after encryption succeeds, forming a
            # real bond rather than a session-only encrypted link.
            response = PairingFeatures(
                io_capability=IO_CAPABILITY_NO_INPUT_NO_OUTPUT,
                oob_data_flag=0x00,
                auth_req=0x00,
                max_key_size=MAX_ENCRYPTION_KEY_SIZE,
                initiator_key_distribution=0x00,
                responder_key_distribution=KEY_DIST_ENC_KEY,
            )
        self._pres = response.encode(PAIRING_RESPONSE)

        if self._use_sc:
            self._local_public_key = self._generate_keypair()
            self.state = State.AWAITING_PUBLIC_KEY
        else:
            self.state = State.AWAITING_CONFIRM
        return self._pres

    def _handle_pairing_confirm(self, body: bytes):
        if self.state is not State.AWAITING_CONFIRM:
            return self._fail(FAILED_UNSPECIFIED_REASON)
        if len(body) != 16:
            return self._fail(FAILED_INVALID_PARAMETERS)

        self._peer_confirm = bytes(body)
        self._own_random = self._random_bytes(16)

        confirm = self._confirm_for(self._own_random)
        self.state = State.AWAITING_RANDOM
        return bytes([PAIRING_CONFIRM]) + confirm

    def _handle_pairing_random(self, body: bytes):
        if self._use_sc:
            return self._handle_sc_pairing_random(body)

        if self.state is not State.AWAITING_RANDOM:
            return self._fail(FAILED_UNSPECIFIED_REASON)
        if len(body) != 16:
            return self._fail(FAILED_INVALID_PARAMETERS)

        self._peer_random = bytes(body)

        # The peer committed to this nonce earlier, so recomputing its confirm
        # value proves it did not choose the nonce after seeing ours.
        if self._confirm_for(self._peer_random) != self._peer_confirm:
            return self._fail(FAILED_CONFIRM_VALUE_FAILED)

        self._short_term_key = crypto.s1(
            self._encrypt, crypto.TK_JUST_WORKS,
            self._own_random, self._peer_random,
        )
        self.state = State.AWAITING_ENCRYPTION
        return bytes([PAIRING_RANDOM]) + self._own_random

    def _handle_public_key(self, body: bytes):
        if self.state is not State.AWAITING_PUBLIC_KEY:
            return self._fail(FAILED_UNSPECIFIED_REASON)
        if len(body) != 64:
            return self._fail(FAILED_INVALID_PARAMETERS)

        self._peer_public_key = bytes(body)
        self._dhkey = self._compute_dhkey(self._peer_public_key)
        self._own_random = self._random_bytes(16)

        # Just Works is the only association model this device offers, so
        # the responder can compute and send its confirm immediately, rather
        # than waiting on a further round trip.
        confirm = crypto.f4(
            self._encrypt,
            self._local_public_key[:32], self._peer_public_key[:32],
            self._own_random, 0,
        )
        self._queued_pdus.append(bytes([PAIRING_CONFIRM]) + confirm)

        self.state = State.AWAITING_SC_RANDOM
        return bytes([PUBLIC_KEY]) + self._local_public_key

    def _handle_sc_pairing_random(self, body: bytes):
        if self.state is not State.AWAITING_SC_RANDOM:
            return self._fail(FAILED_UNSPECIFIED_REASON)
        if len(body) != 16:
            return self._fail(FAILED_INVALID_PARAMETERS)

        self._peer_random = bytes(body)

        self._mackey, self._short_term_key = crypto.f5(
            self._encrypt, self._dhkey,
            self._peer_random, self._own_random,
            self._initiator_address(), self._responder_address(),
        )

        self.state = State.AWAITING_DHKEY_CHECK
        return bytes([PAIRING_RANDOM]) + self._own_random

    def _handle_dhkey_check(self, body: bytes):
        if self.state is not State.AWAITING_DHKEY_CHECK:
            return self._fail(FAILED_UNSPECIFIED_REASON)
        if len(body) != 16:
            return self._fail(FAILED_INVALID_PARAMETERS)

        # Verify what the peer (the initiator) sent, using the io_cap it
        # declared in its own Pairing Request and its own address as a1.
        expected = crypto.f6(
            self._encrypt, self._mackey,
            self._peer_random, self._own_random, _DHKEY_CHECK_R,
            self._preq[1:4],
            self._peer_address_with_type(), self._local_address_with_type(),
        )
        if bytes(body) != expected:
            return self._fail(FAILED_DHKEY_CHECK_FAILED)

        own_check = crypto.f6(
            self._encrypt, self._mackey,
            self._own_random, self._peer_random, _DHKEY_CHECK_R,
            self._pres[1:4],
            self._local_address_with_type(), self._peer_address_with_type(),
        )

        self.state = State.AWAITING_ENCRYPTION
        return bytes([DHKEY_CHECK]) + own_check

    def _peer_address_with_type(self) -> bytes:
        return self._peer_address + bytes([self._peer_address_type])

    def _local_address_with_type(self) -> bytes:
        return self._local_address + bytes([self._local_address_type])

    def _initiator_address(self) -> bytes:
        # This responder never initiates, so the initiator is always the peer.
        return self._peer_address_with_type()

    def _responder_address(self) -> bytes:
        return self._local_address_with_type()

    def long_term_key_for(self, encrypted_diversifier: int, random_number: bytes):
        """
        Supplies the key the controller needs to encrypt the link.

        During legacy pairing the short term key is used, and both the
        diversifier and the random number are zero. A non-zero pair would mean
        the peer is resuming an earlier bond, which is not retained here.
        """
        if self._short_term_key is None:
            return None
        if encrypted_diversifier != 0 or any(random_number):
            return None
        return self._short_term_key

    def note_encryption_change(self, enabled: bool):
        self.state = State.ENCRYPTED if enabled else State.FAILED

    def create_bond_keys(self) -> BondKeys:
        """
        Generates a fresh Long Term Key for the responder key distribution
        phase, to be sent once the current session is encrypted.

        EDIV is left at zero; only Rand needs to be unpredictable, since its
        job is to let a later LE Long Term Key Request name which bond it
        wants resumed; it does not need to be cryptographically hidden the
        way the key itself does.
        """
        return BondKeys(ltk=self._random_bytes(16), ediv=0, rand=self._random_bytes(8))

    def _confirm_for(self, nonce: bytes) -> bytes:
        return crypto.c1(
            self._encrypt,
            crypto.TK_JUST_WORKS,
            nonce,
            self._preq,
            self._pres,
            initiator_address_type=self._peer_address_type,
            initiator_address=self._peer_address,
            responder_address_type=self._local_address_type,
            responder_address=self._local_address,
        )

    def _fail(self, reason: int) -> bytes:
        self.state = State.FAILED
        self.failure_reason = reason
        return pairing_failed(reason)
