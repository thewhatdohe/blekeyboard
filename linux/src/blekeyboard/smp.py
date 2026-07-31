"""
Security Manager pairing, in the responder role.

Implements LE Legacy pairing with the Just Works association model, which is
what a keyboard with no display and no input can offer. The result is an
encrypted link, which HID over GATT requires before a host will accept
input.

Just Works provides no protection against a man in the middle: the temporary
key is zero, so an attacker positioned between the two devices during
pairing can complete it with both. It protects an already-paired session
from passive eavesdropping, nothing more.

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

# Reasons carried by Pairing Failed.
FAILED_OOB_NOT_AVAILABLE = 0x02
FAILED_AUTHENTICATION_REQUIREMENTS = 0x03
FAILED_CONFIRM_VALUE_FAILED = 0x04
FAILED_PAIRING_NOT_SUPPORTED = 0x05
FAILED_ENCRYPTION_KEY_SIZE = 0x06
FAILED_COMMAND_NOT_SUPPORTED = 0x07
FAILED_UNSPECIFIED_REASON = 0x08
FAILED_INVALID_PARAMETERS = 0x0A

# Input and output capabilities. A keyboard peripheral has neither a display
# nor a way for the user to answer a prompt, so it can only offer Just Works.
IO_CAPABILITY_NO_INPUT_NO_OUTPUT = 0x03

# Authentication requirement bits.
AUTH_REQ_BONDING = 0x01
AUTH_REQ_MITM = 0x04
AUTH_REQ_SECURE_CONNECTIONS = 0x08

MAX_ENCRYPTION_KEY_SIZE = 16
MIN_ENCRYPTION_KEY_SIZE = 7

PAIRING_PDU_LENGTH = 7


class State(Enum):
    IDLE = auto()
    AWAITING_CONFIRM = auto()
    AWAITING_RANDOM = auto()
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


class SecurityManager:
    """
    Drives one connection's pairing exchange.

    The caller feeds it inbound SMP payloads and forwards whatever it returns.
    When the peer starts encryption the controller asks for a key, which
    `long_term_key_for` supplies.
    """

    def __init__(self, encrypt, random_bytes, local_address: bytes,
                 local_address_type: int = 0x00):
        self._encrypt = encrypt
        self._random_bytes = random_bytes
        self._local_address = bytes(local_address)
        self._local_address_type = local_address_type

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

    def begin_connection(self, peer_address: bytes, peer_address_type: int):
        """Resets state for a newly connected peer."""
        self.__init__(self._encrypt, self._random_bytes,
                      self._local_address, self._local_address_type)
        self._peer_address = bytes(peer_address)
        self._peer_address_type = peer_address_type

    @property
    def short_term_key(self):
        return self._short_term_key

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

        # A peer insisting on protection against a man in the middle cannot
        # be satisfied by a device with no display and no input.
        if features.auth_req & AUTH_REQ_MITM:
            return self._fail(FAILED_AUTHENTICATION_REQUIREMENTS)

        self._preq = bytes(whole_pdu)

        # Secure Connections is deliberately not claimed, which is what makes
        # the peer fall back to the legacy exchange this implements. No keys
        # are distributed in either direction, so the pairing lasts only for
        # the session.
        response = PairingFeatures(
            io_capability=IO_CAPABILITY_NO_INPUT_NO_OUTPUT,
            oob_data_flag=0x00,
            auth_req=0x00,
            max_key_size=MAX_ENCRYPTION_KEY_SIZE,
            initiator_key_distribution=0x00,
            responder_key_distribution=0x00,
        )
        self._pres = response.encode(PAIRING_RESPONSE)
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
