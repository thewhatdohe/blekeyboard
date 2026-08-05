from blekeyboard.hostprofile import (
    ADDRESS_TYPE_PUBLIC,
    ADDRESS_TYPE_RANDOM,
    HostOS,
    HostSignals,
    guess_host_os,
)

AUTH_REQ_SC = 0x08
AUTH_REQ_CT2 = 0x20
AUTH_REQ_BONDING = 0x01


def test_no_signals_yields_unknown_with_no_confidence():
    guess = guess_host_os(HostSignals())
    assert guess.os is HostOS.UNKNOWN
    assert guess.confidence == "none"


def test_public_address_yields_unknown_desktop():
    # A public BD_ADDR is typical of a desktop adapter; this project has no
    # signal that distinguishes Windows, Linux and macOS from each other.
    guess = guess_host_os(HostSignals(peer_address_type=ADDRESS_TYPE_PUBLIC))
    assert guess.os is HostOS.UNKNOWN
    assert guess.confidence == "low"
    assert guess.reasons


def test_random_address_with_sc_and_ct2_guesses_ios():
    # The exact auth_req pattern this project has directly captured from a
    # real iPhone's Settings-triggered pairing.
    guess = guess_host_os(HostSignals(
        peer_address_type=ADDRESS_TYPE_RANDOM,
        auth_req=AUTH_REQ_BONDING | AUTH_REQ_SC | AUTH_REQ_CT2,
    ))
    assert guess.os is HostOS.IOS
    assert guess.confidence == "medium"


def test_random_address_with_sc_but_no_ct2_does_not_guess_ios():
    # SC alone is not iOS-specific - this project has also captured an iPhone
    # requesting SC without CT2, but never a non-iOS device requesting CT2.
    guess = guess_host_os(HostSignals(
        peer_address_type=ADDRESS_TYPE_RANDOM,
        auth_req=AUTH_REQ_BONDING | AUTH_REQ_SC,
    ))
    assert guess.os is not HostOS.IOS


def test_random_address_with_no_auth_req_yet_defaults_to_android_low_confidence():
    # Before a Pairing Request has arrived (e.g. a resumed bond, which skips
    # SMP entirely), only the address type is known.
    guess = guess_host_os(HostSignals(peer_address_type=ADDRESS_TYPE_RANDOM))
    assert guess.os is HostOS.ANDROID
    assert guess.confidence == "low"


def test_confidence_never_exceeds_medium():
    # No signal set here is strong enough to justify anything higher; this
    # guards against a future change accidentally overclaiming certainty.
    for auth_req in (None, 0x00, AUTH_REQ_SC, AUTH_REQ_SC | AUTH_REQ_CT2):
        for address_type in (ADDRESS_TYPE_PUBLIC, ADDRESS_TYPE_RANDOM, None):
            guess = guess_host_os(HostSignals(
                peer_address_type=address_type, auth_req=auth_req))
            assert guess.confidence in ("none", "low", "medium")
