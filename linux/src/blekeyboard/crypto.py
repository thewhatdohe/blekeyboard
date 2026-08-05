"""
The Security Manager's cryptographic toolbox.

Everything here is built on AES-128, which the controller provides through
the LE Encrypt command, so the package needs no cryptography dependency.

Octet order is the thing to be careful about. SMP PDUs carry 128-bit values
least significant octet first, and the controller's LE Encrypt takes and
returns them the same way, so every value in this module stays in that order
end to end and no swapping is needed. The specification writes these values
most significant octet first, so a constant copied from the specification
text has to be reversed before it is compared against anything here.
"""

BLOCK_SIZE = 16

# The temporary key for Just Works pairing is simply zero. Neither side
# contributes entropy, which is why the result carries no protection against
# a man in the middle.
TK_JUST_WORKS = bytes(BLOCK_SIZE)


def xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def build_c1_p1(preq: bytes, pres: bytes,
                initiator_address_type: int, responder_address_type: int) -> bytes:
    """
    First block mixed into the confirm value.

    The specification writes it as pres || preq || rat || iat, most
    significant first, so in least significant octet order the initiator's
    address type comes first and the pairing response last.
    """
    if len(preq) != 7 or len(pres) != 7:
        raise ValueError("Pairing Request and Response are seven octets each.")

    return bytes([initiator_address_type & 0xFF, responder_address_type & 0xFF]) \
        + bytes(preq) + bytes(pres)


def build_c1_p2(initiator_address: bytes, responder_address: bytes) -> bytes:
    """
    Second block mixed into the confirm value.

    Written as padding || ia || ra, so in least significant octet order the
    responder's address comes first and the padding last.
    """
    if len(initiator_address) != 6 or len(responder_address) != 6:
        raise ValueError("Device addresses are six octets each.")

    return bytes(responder_address) + bytes(initiator_address) + bytes(4)


def c1(encrypt, tk: bytes, rand: bytes, preq: bytes, pres: bytes,
       initiator_address_type: int, initiator_address: bytes,
       responder_address_type: int, responder_address: bytes) -> bytes:
    """
    Confirm value binding a nonce to both sides of the pairing exchange.

    Defined as e(k, e(k, r XOR p1) XOR p2). Because p1 and p2 cover the
    pairing parameters and both device addresses, a confirm value cannot be
    replayed against a different pairing.

    `encrypt` performs one AES-128 block, taking and returning least
    significant octet first.
    """
    if len(tk) != BLOCK_SIZE or len(rand) != BLOCK_SIZE:
        raise ValueError("The key and the nonce are sixteen octets each.")

    p1 = build_c1_p1(preq, pres, initiator_address_type, responder_address_type)
    p2 = build_c1_p2(initiator_address, responder_address)

    return encrypt(tk, xor(encrypt(tk, xor(rand, p1)), p2))


def s1(encrypt, tk: bytes, responder_rand: bytes, initiator_rand: bytes) -> bytes:
    """
    Derives the short term key from both sides' nonces.

    Only the lower half of each nonce contributes. The specification writes
    the combined value as Srand' || Mrand', so in least significant octet
    order the initiator's half comes first.
    """
    if len(responder_rand) != BLOCK_SIZE or len(initiator_rand) != BLOCK_SIZE:
        raise ValueError("Both nonces are sixteen octets.")

    return encrypt(tk, initiator_rand[:8] + responder_rand[:8])


# --- LE Secure Connections ---
#
# f4/f5/f6/g2 are built on AES-CMAC (RFC 4493), not the single-block AES `e`
# that c1/s1 use. This matters for octet order: `encrypt` above is a drop-in
# replacement for the specification's `e` function, taking and returning
# least-significant-octet-first values with no swapping needed by the
# caller (verified empirically against the controller). AES-CMAC, being a
# software construction built from `e`, is specified to run on
# most-significant-octet-first data - a different convention, in the same
# module, for a function built on the same primitive.
#
# This is not a guess: it is ported directly from the Linux kernel's own
# SMP implementation (net/bluetooth/smp.c, functions smp_aes_cmac/smp_f4/
# smp_f5/smp_f6), which reverses both the key and the message before running
# a standard CMAC and reverses the result back afterwards. The message
# layouts below (argument order within the byte string fed to CMAC) are
# copied from the same source, since the specification text's algebraic
# notation does not by itself pin down the wire order unambiguously enough
# to risk transcribing from memory.

_CMAC_RB = 0x87  # The RFC 4493 subkey-generation constant, Rb.


def _reverse(data: bytes) -> bytes:
    return bytes(reversed(data))


def _xor128(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _shift_left_1(block: bytes) -> bytes:
    """Left-shifts a 16-byte block by one bit, most significant octet first."""
    value = int.from_bytes(block, "big") << 1
    return (value & ((1 << 128) - 1)).to_bytes(16, "big")


def _cmac_subkeys(block_cipher_msb, key_msb: bytes):
    """Derives K1/K2 per RFC 4493 Section 2.3, operating MSB-first throughout."""
    l = block_cipher_msb(key_msb, bytes(BLOCK_SIZE))

    k1 = _shift_left_1(l)
    if l[0] & 0x80:
        k1 = _xor128(k1, bytes(15) + bytes([_CMAC_RB]))

    k2 = _shift_left_1(k1)
    if k1[0] & 0x80:
        k2 = _xor128(k2, bytes(15) + bytes([_CMAC_RB]))

    return k1, k2


def _cmac_msb(block_cipher_msb, key_msb: bytes, message_msb: bytes) -> bytes:
    """RFC 4493 AES-CMAC. Both key and message are already MSB-first here."""
    k1, k2 = _cmac_subkeys(block_cipher_msb, key_msb)

    if not message_msb:
        blocks = [b""]
        last_is_complete = False
    else:
        blocks = [message_msb[i:i + BLOCK_SIZE] for i in range(0, len(message_msb), BLOCK_SIZE)]
        last_is_complete = len(blocks[-1]) == BLOCK_SIZE

    if last_is_complete:
        blocks[-1] = _xor128(blocks[-1], k1)
    else:
        padded = blocks[-1] + bytes([0x80]) + bytes(BLOCK_SIZE - len(blocks[-1]) - 1)
        blocks[-1] = _xor128(padded, k2)

    chain = bytes(BLOCK_SIZE)
    for block in blocks:
        chain = block_cipher_msb(key_msb, _xor128(chain, block))
    return chain


def aes_cmac(encrypt, key: bytes, message: bytes) -> bytes:
    """
    AES-CMAC over least-significant-octet-first inputs, matching the
    convention every other function in this module and the SMP wire format
    use. Internally converts to the most-significant-octet-first convention
    CMAC is specified in, runs the standard algorithm, and converts back.
    """
    def block_cipher_msb(key_msb: bytes, block_msb: bytes) -> bytes:
        # Undoes the LSB-first convention `encrypt` already applies, exposing
        # a raw MSB-first block cipher for the CMAC construction to use.
        return _reverse(encrypt(_reverse(key_msb), _reverse(block_msb)))

    mac_msb = _cmac_msb(block_cipher_msb, _reverse(key), _reverse(message))
    return _reverse(mac_msb)


def f4(encrypt, u: bytes, v: bytes, x: bytes, z: int) -> bytes:
    """
    LE Secure Connections confirm value, binding a nonce to both ECDH public
    keys. Defined as AES-CMAC_x(z || v || u) - note the reversed argument
    order relative to how f4 is invoked; the message is built z-first.
    """
    if len(u) != 32 or len(v) != 32:
        raise ValueError("Public key X-coordinates are 32 octets each.")
    if len(x) != BLOCK_SIZE:
        raise ValueError("The CMAC key is sixteen octets.")

    message = bytes([z & 0xFF]) + v + u
    return aes_cmac(encrypt, x, message)


def f5(encrypt, dhkey: bytes, n1: bytes, n2: bytes, a1: bytes, a2: bytes):
    """
    Derives the MacKey and LTK from the ECDH shared secret and both nonces.

    a1/a2 are each a 6-octet device address followed by its 1-octet address
    type. n1/a1 are always the initiator's; n2/a2 the responder's,
    regardless of which side is computing this - both sides derive the same
    two keys from the same absolute (not role-relative) ordering.
    """
    if len(dhkey) != 32:
        raise ValueError("The DHKey is thirty-two octets.")
    if len(n1) != BLOCK_SIZE or len(n2) != BLOCK_SIZE:
        raise ValueError("Both nonces are sixteen octets.")
    if len(a1) != 7 or len(a2) != 7:
        raise ValueError("Both addresses are seven octets (address plus type).")

    btle = bytes([0x65, 0x6C, 0x74, 0x62])
    salt = bytes([
        0xBE, 0x83, 0x60, 0x5A, 0xDB, 0x0B, 0x37, 0x60,
        0x38, 0xA5, 0xF5, 0xAA, 0x91, 0x83, 0x88, 0x6C,
    ])
    length = bytes([0x00, 0x01])  # 256, little-endian

    t = aes_cmac(encrypt, salt, dhkey)

    base = length + a2 + a1 + n2 + n1 + btle
    mackey = aes_cmac(encrypt, t, base + bytes([0]))
    ltk = aes_cmac(encrypt, t, base + bytes([1]))
    return mackey, ltk


def f6(encrypt, w: bytes, n1: bytes, n2: bytes, r: bytes, io_cap: bytes,
       a1: bytes, a2: bytes) -> bytes:
    """
    The DHKey Check value each side sends to prove it derived the same
    MacKey. n1/a1/io_cap always describe whichever side is computing this
    (the sender's own values); n2/a2 the peer's - unlike f5, which always
    orders by initiator/responder regardless of who is asking.
    """
    if len(w) != BLOCK_SIZE:
        raise ValueError("MacKey is sixteen octets.")
    if len(n1) != BLOCK_SIZE or len(n2) != BLOCK_SIZE or len(r) != BLOCK_SIZE:
        raise ValueError("Both nonces and r are sixteen octets.")
    if len(io_cap) != 3:
        raise ValueError("IO capability data is three octets.")
    if len(a1) != 7 or len(a2) != 7:
        raise ValueError("Both addresses are seven octets (address plus type).")

    message = a2 + a1 + io_cap + r + n2 + n1
    return aes_cmac(encrypt, w, message)


def g2(encrypt, u: bytes, v: bytes, x: bytes, y: bytes) -> int:
    """
    The six-digit number shown for Numeric Comparison. Not needed for Just
    Works, which never displays it, but cheap to have alongside f4/f5/f6
    since it shares their construction.
    """
    if len(u) != 32 or len(v) != 32:
        raise ValueError("Public key X-coordinates are 32 octets each.")
    if len(x) != BLOCK_SIZE or len(y) != BLOCK_SIZE:
        raise ValueError("Both x and y are sixteen octets.")

    message = y + v + u
    mac = aes_cmac(encrypt, x, message)
    return int.from_bytes(mac[:4], "little") % 1_000_000


# --- P-256 ECDH, in software ---
#
# LE Secure Connections agrees a shared secret with an ECDH exchange on the
# NIST P-256 curve. A controller can do this through the LE Read Local P-256
# Public Key and LE Generate DHKey commands, and originally this package did.
# In practice, on at least one common adapter, LE Generate DHKey returns a
# Command Status that sets Num_HCI_Command_Packets to zero - "stop sending
# commands" - and never restores the credit, since the follow-up result is
# an LE Meta event, which carries no such credit. Every subsequent HCI
# command (LE Rand, LE Encrypt) is then silently ignored and pairing stalls.
#
# The controller does not actually need to perform the ECDH: only the final
# Long Term Key derived from the shared secret is handed back to it. So the
# key agreement is done here instead, in pure integer arithmetic with no
# dependency, producing keys and a DHKey in exactly the octet order the
# controller commands used (X then Y, each least significant octet first),
# so f4/f5/f6 and the wire format are untouched.
#
# The arithmetic is plain affine point math: correctness, not resistance to
# timing side channels, is the goal, and it is cross-checked against an
# independent implementation in the test suite before being trusted.

# NIST P-256 (secp256r1) domain parameters.
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

P256_KEY_SIZE = 32  # Octets per coordinate.


def _p256_on_curve(x: int, y: int) -> bool:
    """Whether (x, y) satisfies y^2 = x^3 + a*x + b over the field."""
    if not (0 <= x < _P256_P and 0 <= y < _P256_P):
        return False
    return (y * y - (x * x * x + _P256_A * x + _P256_B)) % _P256_P == 0


def _p256_add(point_a, point_b):
    """Adds two affine points, using None for the point at infinity."""
    if point_a is None:
        return point_b
    if point_b is None:
        return point_a

    x1, y1 = point_a
    x2, y2 = point_b

    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None  # Mutual inverses sum to the point at infinity.

    if point_a == point_b:
        slope = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P

    x3 = (slope * slope - x1 - x2) % _P256_P
    y3 = (slope * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def _p256_scalar_mult(scalar: int, point):
    """Multiplies a point by a scalar via double-and-add."""
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        scalar >>= 1
    return result


def _encode_public_key(x: int, y: int) -> bytes:
    """Serialises a public point as 64 octets, X then Y, each LSB first."""
    return x.to_bytes(P256_KEY_SIZE, "little") + y.to_bytes(P256_KEY_SIZE, "little")


def generate_p256_keypair(random_scalar=None):
    """
    Generates a P-256 key pair for one Secure Connections exchange.

    Returns the private scalar as an integer and the public key as 64 octets
    (X then Y, each least significant octet first), matching what the
    controller's LE Read Local P-256 Public Key command produced.

    `random_scalar`, if given, supplies the private scalar for a
    deterministic test; otherwise it is drawn from the system CSPRNG.
    """
    if random_scalar is None:
        import secrets
        private = secrets.randbelow(_P256_N - 1) + 1
    else:
        private = random_scalar

    x, y = _p256_scalar_mult(private, (_P256_GX, _P256_GY))
    return private, _encode_public_key(x, y)


def p256_compute_dhkey(private_scalar: int, peer_public_key: bytes) -> bytes:
    """
    Computes the ECDH shared secret from a private scalar and a peer's key.

    `peer_public_key` is 64 octets (X then Y, each least significant octet
    first), as received in the peer's Public Key PDU. Returns the 32-octet
    X coordinate of the shared point, least significant octet first, matching
    what the controller's LE Generate DHKey command produced.

    The peer's point is checked to be on the curve first: a point that is not
    could be an invalid-curve attack aimed at leaking the private scalar.
    """
    if len(peer_public_key) != 2 * P256_KEY_SIZE:
        raise ValueError("A public key is sixty-four octets.")

    peer_x = int.from_bytes(peer_public_key[:P256_KEY_SIZE], "little")
    peer_y = int.from_bytes(peer_public_key[P256_KEY_SIZE:], "little")

    if not _p256_on_curve(peer_x, peer_y):
        raise ValueError("The peer public key is not a point on P-256.")

    shared = _p256_scalar_mult(private_scalar, (peer_x, peer_y))
    if shared is None:
        raise ValueError("The ECDH exchange produced the point at infinity.")

    shared_x, _ = shared
    return shared_x.to_bytes(P256_KEY_SIZE, "little")
