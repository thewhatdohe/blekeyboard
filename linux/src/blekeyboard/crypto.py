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
