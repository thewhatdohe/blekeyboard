"""
Cross-checks our hand-rolled P-256 ECDH against a real, independent
implementation (the `cryptography` library), rather than trusting the curve
arithmetic and the domain constants were transcribed correctly by inspection.

Skipped automatically if `cryptography` is not installed - it is a dev-only
verification aid, not a runtime dependency of the package.
"""
import pytest

from blekeyboard import crypto

pytest.importorskip("cryptography", reason="cryptography not installed")
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402


def _reference_public_key(x_le, y_le):
    x = int.from_bytes(x_le, "little")
    y = int.from_bytes(y_le, "little")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def test_generated_public_key_is_on_the_curve():
    for _ in range(20):
        _private, public = crypto.generate_p256_keypair()
        x = int.from_bytes(public[:32], "little")
        y = int.from_bytes(public[32:], "little")
        assert crypto._p256_on_curve(x, y)


def test_generated_public_key_matches_the_reference_for_the_same_scalar():
    # A fixed private scalar must produce the same public point the reference
    # library derives from it - proof the base point and field math agree.
    scalar = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    _private, public = crypto.generate_p256_keypair(random_scalar=scalar)

    reference = ec.derive_private_key(scalar, ec.SECP256R1()).public_key().public_numbers()
    assert int.from_bytes(public[:32], "little") == reference.x
    assert int.from_bytes(public[32:], "little") == reference.y


def test_dhkey_matches_the_reference_across_many_pairs():
    for _ in range(25):
        # Our side, in software.
        our_private, our_public = crypto.generate_p256_keypair()

        # The peer, using the reference library.
        peer_private = ec.generate_private_key(ec.SECP256R1())
        peer_numbers = peer_private.public_key().public_numbers()
        peer_public = peer_numbers.x.to_bytes(32, "little") \
            + peer_numbers.y.to_bytes(32, "little")

        # Our DHKey: our private scalar against the peer's public key.
        ours = crypto.p256_compute_dhkey(our_private, peer_public)
        ours_x = int.from_bytes(ours, "little")

        # The reference DHKey: the peer's private key against our public key.
        # A correct exchange has both sides arrive at the same X coordinate.
        reference_shared = peer_private.exchange(ec.ECDH(), _reference_public_key(
            our_public[:32], our_public[32:]))
        reference_x = int.from_bytes(reference_shared, "big")

        assert ours_x == reference_x


def test_a_public_key_off_the_curve_is_rejected():
    # An X/Y pair that is not a curve point must be refused rather than fed
    # into the scalar multiplication, where it could leak the private scalar.
    our_private, _our_public = crypto.generate_p256_keypair()
    bogus = (1).to_bytes(32, "little") + (1).to_bytes(32, "little")
    with pytest.raises(ValueError):
        crypto.p256_compute_dhkey(our_private, bogus)
