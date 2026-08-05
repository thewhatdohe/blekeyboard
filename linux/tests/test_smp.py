import pytest

from blekeyboard import crypto, smp
from blekeyboard.smp import PairingFeatures, SecurityManager, State

LOCAL_ADDRESS = bytes.fromhex("B6B5B4B3B2B1")
PEER_ADDRESS = bytes.fromhex("A6A5A4A3A2A1")
LOCAL_ADDRESS_TYPE = 0x00
PEER_ADDRESS_TYPE = 0x01
LOCAL_ADDRESS_WITH_TYPE = LOCAL_ADDRESS + bytes([LOCAL_ADDRESS_TYPE])
PEER_ADDRESS_WITH_TYPE = PEER_ADDRESS + bytes([PEER_ADDRESS_TYPE])

# A deterministic stand-in public key, distinct from whatever the peer sends.
OWN_PUBLIC_KEY = bytes(range(64))
PEER_PUBLIC_KEY = bytes(range(100, 164))


def fake_encrypt(key, block):
    """Deterministic stand-in for AES; only the protocol flow is under test."""
    return bytes(((b * 7) + key[0] + 13) & 0xFF for b in block)


def counting_random(seed=0):
    state = {"n": seed}

    def generate(length):
        state["n"] += 1
        return bytes(((state["n"] * 31 + i) & 0xFF) for i in range(length))

    return generate


def make_manager():
    manager = SecurityManager(fake_encrypt, counting_random(), LOCAL_ADDRESS)
    manager.begin_connection(PEER_ADDRESS, peer_address_type=0x01)
    return manager


def fake_generate_keypair():
    return OWN_PUBLIC_KEY


def fake_compute_dhkey(peer_public_key):
    """Deterministic stand-in for ECDH; only the protocol flow is under test."""
    return bytes(((b * 3) + 1) & 0xFF for b in peer_public_key[:32])


def make_sc_manager():
    manager = SecurityManager(
        fake_encrypt, counting_random(), LOCAL_ADDRESS,
        generate_keypair=fake_generate_keypair,
        compute_dhkey=fake_compute_dhkey,
    )
    manager.begin_connection(PEER_ADDRESS, peer_address_type=PEER_ADDRESS_TYPE)
    return manager


def sc_pairing_request(auth_req=smp.AUTH_REQ_SECURE_CONNECTIONS | smp.AUTH_REQ_BONDING):
    return pairing_request(auth_req=auth_req)


def pairing_request(io_capability=smp.IO_CAPABILITY_NO_INPUT_NO_OUTPUT,
                    oob=0x00, auth_req=0x01, max_key_size=16,
                    initiator_keys=0x00, responder_keys=0x00):
    return PairingFeatures(
        io_capability=io_capability,
        oob_data_flag=oob,
        auth_req=auth_req,
        max_key_size=max_key_size,
        initiator_key_distribution=initiator_keys,
        responder_key_distribution=responder_keys,
    ).encode(smp.PAIRING_REQUEST)


def drive_to_confirm(manager):
    """Runs the exchange up to the point the peer sends its random."""
    request = pairing_request()
    manager.handle_pdu(request)

    # The peer picks a nonce and commits to it.
    peer_random = bytes(range(16))
    peer_confirm = crypto.c1(
        fake_encrypt, crypto.TK_JUST_WORKS, peer_random,
        request, manager._pres,
        initiator_address_type=0x01, initiator_address=PEER_ADDRESS,
        responder_address_type=0x00, responder_address=LOCAL_ADDRESS,
    )
    manager.handle_pdu(bytes([smp.PAIRING_CONFIRM]) + peer_confirm)
    return peer_random


def drive_sc_to_dhkey_check(manager, peer_random=bytes(range(16))):
    """
    Runs the SC exchange up to the point the peer sends its DHKey Check.

    Returns (dhkey, peer_confirm_pdu, own_random), everything a test needs to
    independently recompute what the manager should have derived at each step.
    """
    manager.handle_pdu(sc_pairing_request())

    public_key_response = manager.handle_pdu(bytes([smp.PUBLIC_KEY]) + PEER_PUBLIC_KEY)
    queued = manager.drain_queued_pdus()

    random_response = manager.handle_pdu(bytes([smp.PAIRING_RANDOM]) + peer_random)
    own_random = random_response[1:]

    dhkey = fake_compute_dhkey(PEER_PUBLIC_KEY)
    return dhkey, public_key_response, queued, own_random


class TestPeerFeatures:
    def test_none_before_a_pairing_request_arrives(self):
        assert make_manager().peer_features is None

    def test_reflects_the_peers_declared_auth_req_and_io_capability(self):
        manager = make_manager()
        manager.handle_pdu(pairing_request(io_capability=0x04, auth_req=0x2D))

        features = manager.peer_features
        assert features.io_capability == 0x04
        assert features.auth_req == 0x2D


class TestPairingRequest:
    def test_response_offers_just_works(self):
        manager = make_manager()
        response = manager.handle_pdu(pairing_request())

        assert response[0] == smp.PAIRING_RESPONSE
        features = PairingFeatures.parse(response[1:])
        assert features.io_capability == smp.IO_CAPABILITY_NO_INPUT_NO_OUTPUT
        assert features.oob_data_flag == 0x00
        assert manager.state is State.AWAITING_CONFIRM

    def test_secure_connections_is_not_claimed(self):
        # Declining it is what makes the peer use the legacy exchange this
        # implementation supports.
        manager = make_manager()
        response = manager.handle_pdu(
            pairing_request(auth_req=smp.AUTH_REQ_SECURE_CONNECTIONS | 0x01))
        features = PairingFeatures.parse(response[1:])
        assert not features.auth_req & smp.AUTH_REQ_SECURE_CONNECTIONS

    def test_nothing_is_requested_from_the_peer(self):
        # A keyboard never reads anything back from the central, so there is
        # no reason to ask it to distribute keys of its own.
        manager = make_manager()
        response = manager.handle_pdu(pairing_request(initiator_keys=0x07,
                                                      responder_keys=0x07))
        features = PairingFeatures.parse(response[1:])
        assert features.initiator_key_distribution == 0x00

    def test_responder_declares_it_will_distribute_an_encryption_key(self):
        # Without this, several hosts never treat the link as a real bond,
        # regardless of whether the current session happens to be encrypted.
        manager = make_manager()
        response = manager.handle_pdu(pairing_request(initiator_keys=0x07,
                                                      responder_keys=0x07))
        features = PairingFeatures.parse(response[1:])
        assert features.responder_key_distribution == smp.KEY_DIST_ENC_KEY

    def test_a_mitm_request_does_not_prevent_pairing(self):
        # A peer may ask for MITM protection, but a device with no display
        # and no input can only ever offer Just Works - the request is
        # simply not satisfiable, not a reason to refuse pairing outright.
        manager = make_manager()
        response = manager.handle_pdu(pairing_request(auth_req=smp.AUTH_REQ_MITM))

        assert response[0] == smp.PAIRING_RESPONSE
        assert manager.state is State.AWAITING_CONFIRM

    def test_out_of_band_data_is_refused(self):
        manager = make_manager()
        response = manager.handle_pdu(pairing_request(oob=0x01))
        assert response == smp.pairing_failed(smp.FAILED_OOB_NOT_AVAILABLE)

    @pytest.mark.parametrize("size", [0, 6, 17, 255])
    def test_unusable_key_sizes_are_refused(self, size):
        manager = make_manager()
        response = manager.handle_pdu(pairing_request(max_key_size=size))
        assert response == smp.pairing_failed(smp.FAILED_ENCRYPTION_KEY_SIZE)

    def test_truncated_request_is_refused(self):
        manager = make_manager()
        response = manager.handle_pdu(bytes([smp.PAIRING_REQUEST, 0x03, 0x00]))
        assert response == smp.pairing_failed(smp.FAILED_INVALID_PARAMETERS)


class TestConfirmExchange:
    def test_confirm_is_answered_with_our_own(self):
        manager = make_manager()
        manager.handle_pdu(pairing_request())

        response = manager.handle_pdu(bytes([smp.PAIRING_CONFIRM]) + bytes(16))
        assert response[0] == smp.PAIRING_CONFIRM
        assert len(response) == 17
        assert manager.state is State.AWAITING_RANDOM

    def test_confirm_before_a_request_is_refused(self):
        manager = make_manager()
        response = manager.handle_pdu(bytes([smp.PAIRING_CONFIRM]) + bytes(16))
        assert response[0] == smp.PAIRING_FAILED

    def test_wrong_length_confirm_is_refused(self):
        manager = make_manager()
        manager.handle_pdu(pairing_request())
        response = manager.handle_pdu(bytes([smp.PAIRING_CONFIRM]) + bytes(8))
        assert response == smp.pairing_failed(smp.FAILED_INVALID_PARAMETERS)


class TestRandomExchange:
    def test_matching_confirm_yields_our_random_and_a_key(self):
        manager = make_manager()
        peer_random = drive_to_confirm(manager)

        response = manager.handle_pdu(bytes([smp.PAIRING_RANDOM]) + peer_random)
        assert response[0] == smp.PAIRING_RANDOM
        assert len(response) == 17
        assert manager.state is State.AWAITING_ENCRYPTION
        assert manager.short_term_key is not None

    def test_key_matches_an_independent_derivation(self):
        manager = make_manager()
        peer_random = drive_to_confirm(manager)
        response = manager.handle_pdu(bytes([smp.PAIRING_RANDOM]) + peer_random)

        our_random = response[1:]
        expected = crypto.s1(fake_encrypt, crypto.TK_JUST_WORKS, our_random, peer_random)
        assert manager.short_term_key == expected

    def test_a_random_that_does_not_match_the_commitment_is_refused(self):
        # The peer must not be able to pick its nonce after seeing ours.
        manager = make_manager()
        drive_to_confirm(manager)

        response = manager.handle_pdu(bytes([smp.PAIRING_RANDOM]) + bytes(16))
        assert response == smp.pairing_failed(smp.FAILED_CONFIRM_VALUE_FAILED)
        assert manager.short_term_key is None

    def test_random_out_of_order_is_refused(self):
        manager = make_manager()
        manager.handle_pdu(pairing_request())
        response = manager.handle_pdu(bytes([smp.PAIRING_RANDOM]) + bytes(16))
        assert response[0] == smp.PAIRING_FAILED


class TestLongTermKey:
    def _paired(self):
        manager = make_manager()
        peer_random = drive_to_confirm(manager)
        manager.handle_pdu(bytes([smp.PAIRING_RANDOM]) + peer_random)
        return manager

    def test_key_is_offered_for_a_fresh_pairing(self):
        manager = self._paired()
        assert manager.long_term_key_for(0, bytes(8)) == manager.short_term_key

    def test_no_key_before_pairing_completes(self):
        assert make_manager().long_term_key_for(0, bytes(8)) is None

    def test_a_request_to_resume_an_old_bond_is_declined(self):
        # A non-zero diversifier means the peer expects a previously
        # distributed key. SecurityManager only ever holds the current
        # session's key; matching a resumed bond is Link's job, since a
        # bond outlives any single SecurityManager instance.
        manager = self._paired()
        assert manager.long_term_key_for(0x1234, bytes(8)) is None


class TestBondKeyGeneration:
    def test_generated_keys_are_the_expected_lengths(self):
        keys = make_manager().create_bond_keys()
        assert len(keys.ltk) == 16
        assert len(keys.rand) == 8

    def test_ediv_is_zero(self):
        # Only Rand needs to be unpredictable; EDIV is just along for the ride.
        assert make_manager().create_bond_keys().ediv == 0

    def test_successive_calls_produce_different_keys(self):
        manager = make_manager()
        first = manager.create_bond_keys()
        second = manager.create_bond_keys()
        assert first.ltk != second.ltk
        assert first.rand != second.rand

    def test_encoded_pdus_carry_the_key_and_the_ediv_rand_pair(self):
        keys = smp.BondKeys(ltk=bytes(range(16)), ediv=0x1234, rand=bytes(range(100, 108)))
        encryption_information, master_identification = keys.encode_pdus()

        assert encryption_information[0] == smp.ENCRYPTION_INFORMATION
        assert encryption_information[1:] == keys.ltk

        assert master_identification[0] == smp.MASTER_IDENTIFICATION
        assert int.from_bytes(master_identification[1:3], "little") == keys.ediv
        assert master_identification[3:] == keys.rand

    def test_matches_only_the_exact_ediv_and_rand_it_was_given(self):
        keys = smp.BondKeys(ltk=bytes(16), ediv=0x1234, rand=bytes(range(8)))
        assert keys.matches(0x1234, bytes(range(8)))
        assert not keys.matches(0x1235, bytes(range(8)))
        assert not keys.matches(0x1234, bytes(range(1, 9)))


class TestLifecycle:
    def test_encryption_change_completes_the_exchange(self):
        manager = make_manager()
        manager.note_encryption_change(True)
        assert manager.state is State.ENCRYPTED

    def test_failed_encryption_is_recorded(self):
        manager = make_manager()
        manager.note_encryption_change(False)
        assert manager.state is State.FAILED

    def test_peer_failure_is_recorded_without_a_reply(self):
        manager = make_manager()
        assert manager.handle_pdu(bytes([smp.PAIRING_FAILED, 0x08])) is None
        assert manager.state is State.FAILED
        assert manager.failure_reason == 0x08

    def test_key_distribution_pdus_are_tolerated(self):
        manager = make_manager()
        assert manager.handle_pdu(bytes([smp.IDENTITY_INFORMATION]) + bytes(16)) is None

    def test_unknown_command_is_refused(self):
        manager = make_manager()
        response = manager.handle_pdu(bytes([0x7F]))
        assert response == smp.pairing_failed(smp.FAILED_COMMAND_NOT_SUPPORTED)

    def test_empty_payload_is_ignored(self):
        assert make_manager().handle_pdu(b"") is None

    def test_a_new_connection_clears_previous_state(self):
        manager = make_manager()
        drive_to_confirm(manager)

        manager.begin_connection(PEER_ADDRESS, 0x01)
        assert manager.state is State.IDLE
        assert manager.short_term_key is None


class TestSecureConnectionsNegotiation:
    def test_sc_is_claimed_when_the_peer_offers_it_and_a_keypair_is_available(self):
        manager = make_sc_manager()
        response = manager.handle_pdu(sc_pairing_request())

        features = PairingFeatures.parse(response[1:])
        assert features.auth_req & smp.AUTH_REQ_SECURE_CONNECTIONS
        assert features.auth_req & smp.AUTH_REQ_BONDING
        # SC's key exchange already produces a durable LTK, so there is
        # nothing left to distribute in a separate phase.
        assert features.responder_key_distribution == 0x00
        assert manager.use_sc
        assert manager.state is State.AWAITING_PUBLIC_KEY

    def test_sc_is_not_claimed_when_the_peer_does_not_offer_it(self):
        manager = make_sc_manager()
        response = manager.handle_pdu(pairing_request(auth_req=smp.AUTH_REQ_BONDING))

        features = PairingFeatures.parse(response[1:])
        assert not features.auth_req & smp.AUTH_REQ_SECURE_CONNECTIONS
        assert not manager.use_sc
        assert manager.state is State.AWAITING_CONFIRM

    def test_sc_is_not_claimed_without_keypair_callbacks(self):
        # A manager built without generate_keypair/compute_dhkey (the legacy
        # constructor call this project still uses in some tests) can never
        # offer SC, no matter what the peer asks for.
        manager = make_manager()
        response = manager.handle_pdu(
            pairing_request(auth_req=smp.AUTH_REQ_SECURE_CONNECTIONS | smp.AUTH_REQ_BONDING))

        features = PairingFeatures.parse(response[1:])
        assert not features.auth_req & smp.AUTH_REQ_SECURE_CONNECTIONS
        assert not manager.use_sc


class TestSecureConnectionsKeyExchange:
    def test_public_key_is_answered_with_our_own_and_a_queued_confirm(self):
        manager = make_sc_manager()
        manager.handle_pdu(sc_pairing_request())

        response = manager.handle_pdu(bytes([smp.PUBLIC_KEY]) + PEER_PUBLIC_KEY)
        assert response == bytes([smp.PUBLIC_KEY]) + OWN_PUBLIC_KEY

        queued = manager.drain_queued_pdus()
        assert len(queued) == 1
        assert queued[0][0] == smp.PAIRING_CONFIRM
        assert len(queued[0]) == 17
        assert manager.state is State.AWAITING_SC_RANDOM

    def test_wrong_length_public_key_is_refused(self):
        manager = make_sc_manager()
        manager.handle_pdu(sc_pairing_request())
        response = manager.handle_pdu(bytes([smp.PUBLIC_KEY]) + bytes(63))
        assert response == smp.pairing_failed(smp.FAILED_INVALID_PARAMETERS)

    def test_confirm_matches_an_independent_f4_derivation(self):
        manager = make_sc_manager()
        manager.handle_pdu(sc_pairing_request())
        manager.handle_pdu(bytes([smp.PUBLIC_KEY]) + PEER_PUBLIC_KEY)
        queued_confirm = manager.drain_queued_pdus()[0]

        random_response = manager.handle_pdu(bytes([smp.PAIRING_RANDOM]) + bytes(range(16)))
        own_random = random_response[1:]

        # Responder's own confirm always uses u = own key, v = peer's key,
        # regardless of which side computes it.
        expected = crypto.f4(fake_encrypt, OWN_PUBLIC_KEY[:32], PEER_PUBLIC_KEY[:32],
                             own_random, 0)
        assert queued_confirm[1:] == expected

    def test_sc_random_yields_our_random_and_a_key_matching_independent_f5(self):
        manager = make_sc_manager()
        peer_random = bytes(range(16))
        dhkey, _, _, own_random = drive_sc_to_dhkey_check(manager, peer_random)

        assert manager.state is State.AWAITING_DHKEY_CHECK
        assert manager.short_term_key is not None

        _, expected_ltk = crypto.f5(
            fake_encrypt, dhkey, peer_random, own_random,
            PEER_ADDRESS_WITH_TYPE, LOCAL_ADDRESS_WITH_TYPE,
        )
        assert manager.short_term_key == expected_ltk

    def test_wrong_length_sc_random_is_refused(self):
        manager = make_sc_manager()
        manager.handle_pdu(sc_pairing_request())
        manager.handle_pdu(bytes([smp.PUBLIC_KEY]) + PEER_PUBLIC_KEY)
        manager.drain_queued_pdus()

        response = manager.handle_pdu(bytes([smp.PAIRING_RANDOM]) + bytes(8))
        assert response == smp.pairing_failed(smp.FAILED_INVALID_PARAMETERS)


class TestSecureConnectionsDHKeyCheck:
    def _expected_mackey_and_dhkey(self, dhkey, peer_random, own_random):
        mackey, _ = crypto.f5(
            fake_encrypt, dhkey, peer_random, own_random,
            PEER_ADDRESS_WITH_TYPE, LOCAL_ADDRESS_WITH_TYPE,
        )
        return mackey

    def test_matching_dhkey_check_yields_our_own_and_completes_the_exchange(self):
        manager = make_sc_manager()
        peer_random = bytes(range(16))
        dhkey, _, _, own_random = drive_sc_to_dhkey_check(manager, peer_random)
        mackey = self._expected_mackey_and_dhkey(dhkey, peer_random, own_random)

        # The peer computes its check using its own nonce first, our nonce
        # second, and the io_cap it declared in its own Pairing Request.
        peer_check = crypto.f6(
            fake_encrypt, mackey, peer_random, own_random, smp._DHKEY_CHECK_R,
            sc_pairing_request()[1:4],
            PEER_ADDRESS_WITH_TYPE, LOCAL_ADDRESS_WITH_TYPE,
        )

        response = manager.handle_pdu(bytes([smp.DHKEY_CHECK]) + peer_check)
        assert response[0] == smp.DHKEY_CHECK
        assert manager.state is State.AWAITING_ENCRYPTION

        expected_own_check = crypto.f6(
            fake_encrypt, mackey, own_random, peer_random, smp._DHKEY_CHECK_R,
            manager._pres[1:4],
            LOCAL_ADDRESS_WITH_TYPE, PEER_ADDRESS_WITH_TYPE,
        )
        assert response[1:] == expected_own_check

    def test_mismatched_dhkey_check_is_refused(self):
        manager = make_sc_manager()
        drive_sc_to_dhkey_check(manager)

        response = manager.handle_pdu(bytes([smp.DHKEY_CHECK]) + bytes(16))
        assert response == smp.pairing_failed(smp.FAILED_DHKEY_CHECK_FAILED)
        assert manager.state is State.FAILED

    def test_wrong_length_dhkey_check_is_refused(self):
        manager = make_sc_manager()
        drive_sc_to_dhkey_check(manager)

        response = manager.handle_pdu(bytes([smp.DHKEY_CHECK]) + bytes(8))
        assert response == smp.pairing_failed(smp.FAILED_INVALID_PARAMETERS)

    def test_dhkey_check_out_of_order_is_refused(self):
        manager = make_sc_manager()
        response = manager.handle_pdu(bytes([smp.DHKEY_CHECK]) + bytes(16))
        assert response[0] == smp.PAIRING_FAILED

    def test_long_term_key_is_offered_after_sc_pairing_too(self):
        manager = make_sc_manager()
        peer_random = bytes(range(16))
        dhkey, _, _, own_random = drive_sc_to_dhkey_check(manager, peer_random)
        mackey = self._expected_mackey_and_dhkey(dhkey, peer_random, own_random)
        peer_check = crypto.f6(
            fake_encrypt, mackey, peer_random, own_random, smp._DHKEY_CHECK_R,
            sc_pairing_request()[1:4],
            PEER_ADDRESS_WITH_TYPE, LOCAL_ADDRESS_WITH_TYPE,
        )
        manager.handle_pdu(bytes([smp.DHKEY_CHECK]) + peer_check)

        assert manager.long_term_key_for(0, bytes(8)) == manager.short_term_key


class TestSecureConnectionsPairingConfirmIsUnused:
    def test_a_pairing_confirm_received_during_sc_is_refused(self):
        # Only the responder sends a confirm in the Just Works SC flow; this
        # device should never receive one from the peer.
        manager = make_sc_manager()
        manager.handle_pdu(sc_pairing_request())
        response = manager.handle_pdu(bytes([smp.PAIRING_CONFIRM]) + bytes(16))
        assert response[0] == smp.PAIRING_FAILED
