import pytest

from blekeyboard import crypto, smp
from blekeyboard.smp import PairingFeatures, SecurityManager, State

LOCAL_ADDRESS = bytes.fromhex("B6B5B4B3B2B1")
PEER_ADDRESS = bytes.fromhex("A6A5A4A3A2A1")


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

    def test_no_keys_are_distributed(self):
        manager = make_manager()
        response = manager.handle_pdu(pairing_request(initiator_keys=0x07,
                                                      responder_keys=0x07))
        features = PairingFeatures.parse(response[1:])
        assert features.initiator_key_distribution == 0x00
        assert features.responder_key_distribution == 0x00

    def test_demand_for_man_in_the_middle_protection_is_refused(self):
        manager = make_manager()
        response = manager.handle_pdu(pairing_request(auth_req=smp.AUTH_REQ_MITM))

        assert response == smp.pairing_failed(smp.FAILED_AUTHENTICATION_REQUIREMENTS)
        assert manager.state is State.FAILED

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
        # A non-zero diversifier means the peer expects a stored key, and
        # nothing is stored because this implementation does not bond.
        manager = self._paired()
        assert manager.long_term_key_for(0x1234, bytes(8)) is None
        assert manager.long_term_key_for(0, bytes(range(8))) is None


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
