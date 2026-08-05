"""
Cross-checks our hand-rolled AES-CMAC against a real, independent AES-CMAC
implementation (pycryptodome), rather than trusting the RFC 4493 algorithm
was transcribed correctly by inspection alone.

Skipped automatically if pycryptodome is not installed - it is a dev-only
verification aid, not a runtime dependency of the package.
"""
import os
import random

import pytest

from blekeyboard import crypto

pycryptodome = pytest.importorskip("Crypto", reason="pycryptodome not installed")
from Crypto.Cipher import AES as ReferenceAES  # noqa: E402
from Crypto.Hash import CMAC as ReferenceCMAC  # noqa: E402


def software_encrypt(key, block):
    """Our LE-native convention: reverse in, raw AES, reverse out."""
    return ReferenceAES.new(bytes(key[::-1]), ReferenceAES.MODE_ECB) \
        .encrypt(bytes(block[::-1]))[::-1]


def reference_cmac_lsb(key_lsb, message_lsb):
    """
    The reference library's CMAC, adapted to our LSB-first convention.

    `crypto.aes_cmac` treats its whole key and message as one LSB-first
    blob and reverses that whole blob (not field by field) to get the
    MSB-first form the standard algorithm runs on - the same trick
    `f4`/`f5`/`f6` rely on, building their message in block-reversed order
    so a single whole-buffer reversal lands every field MSB-first in the
    right order. A correct cross-check has to apply that same whole-buffer
    reversal before calling the reference and after reading its result.
    """
    mac = ReferenceCMAC.new(key_lsb[::-1], ciphermod=ReferenceAES)
    mac.update(message_lsb[::-1])
    return mac.digest()[::-1]


@pytest.mark.parametrize("length", [0, 1, 5, 15, 16, 17, 32, 33, 65, 80])
def test_matches_reference_cmac_at_this_length(length):
    rng = random.Random(f"cmac-{length}")
    key = bytes(rng.randrange(256) for _ in range(16))
    message = bytes(rng.randrange(256) for _ in range(length))

    assert crypto.aes_cmac(software_encrypt, key, message) == reference_cmac_lsb(key, message)


def test_matches_reference_cmac_across_many_random_cases():
    rng = random.Random(1234)
    mismatches = []

    for _ in range(200):
        key = bytes(rng.randrange(256) for _ in range(16))
        length = rng.choice([0, 1, 5, 15, 16, 17, 32, 33, 65, 80])
        message = bytes(rng.randrange(256) for _ in range(length))

        ours = crypto.aes_cmac(software_encrypt, key, message)
        theirs = reference_cmac_lsb(key, message)
        if ours != theirs:
            mismatches.append((length, key.hex()))

    assert not mismatches, f"{len(mismatches)} mismatches, e.g. {mismatches[:5]}"
