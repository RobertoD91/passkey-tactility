# SPDX-License-Identifier: Apache-2.0
"""CTAP2 core: getInfo, makeCredential, getAssertion, resident credentials, reset, user presence."""
import os

import pytest
from fido2.attestation import PackedAttestation
from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID
from fido2.webauthn import AuthenticatorData

RP = {"id": "example.com", "name": "Example"}
USER = {"id": b"user-id-1", "name": "alice", "displayName": "Alice"}
KEY_PARAMS = [{"type": "public-key", "alg": -7}]
AAGUID = b"tact-passkey-1.0"


def make_credential(ctap2, rp=RP, user=USER, **kwargs):
    client_data_hash = os.urandom(32)
    attestation = ctap2.make_credential(client_data_hash, rp, user, KEY_PARAMS, **kwargs)
    return client_data_hash, attestation


def test_ctaphid_ping_and_wink(device):
    payload = os.urandom(100)
    assert device.call(CTAPHID.PING, payload) == payload
    assert device.call(CTAPHID.WINK) == b""


def test_get_info(device):
    info = Ctap2(device).info
    assert "FIDO_2_0" in info.versions and "FIDO_2_1" in info.versions and "U2F_V2" in info.versions
    assert info.aaguid == AAGUID
    assert info.options["rk"] is True
    assert info.options["up"] is True
    assert info.options["clientPin"] is False
    assert info.options["credMgmt"] is True
    assert info.options["pinUvAuthToken"] is True
    assert "hmac-secret" in info.extensions and "credProtect" in info.extensions
    assert info.pin_uv_protocols == [2, 1]
    assert info.max_msg_size >= 1024
    assert info.transports == ["usb"]
    assert info.algorithms == [{"alg": -7, "type": "public-key"}]


def test_make_credential_self_attestation(device):
    ctap2 = Ctap2(device)
    client_data_hash, attestation = make_credential(ctap2)
    assert attestation.fmt == "packed"
    auth_data = attestation.auth_data
    assert auth_data.rp_id_hash == __import__("hashlib").sha256(b"example.com").digest()
    assert auth_data.flags & AuthenticatorData.FLAG.UP
    assert auth_data.flags & AuthenticatorData.FLAG.AT
    assert not auth_data.flags & AuthenticatorData.FLAG.UV
    assert auth_data.credential_data.aaguid == AAGUID
    assert len(auth_data.credential_data.credential_id) == 50
    assert isinstance(auth_data.credential_data.public_key, ES256)
    # Self attestation: the signature verifies with the credential's own key.
    PackedAttestation().verify(attestation.att_stmt, auth_data, client_data_hash)


def test_get_assertion_with_allow_list(device):
    ctap2 = Ctap2(device)
    _, attestation = make_credential(ctap2)
    cred = attestation.auth_data.credential_data
    client_data_hash = os.urandom(32)
    assertion = ctap2.get_assertion(RP["id"], client_data_hash, allow_list=[{"type": "public-key", "id": cred.credential_id}])
    assert assertion.credential["id"] == cred.credential_id
    assert assertion.auth_data.flags & AuthenticatorData.FLAG.UP
    assert assertion.auth_data.counter > attestation.auth_data.counter
    assertion.verify(client_data_hash, cred.public_key)
    # A non-discoverable credential carries no user entity.
    assert assertion.user is None
    assert assertion.number_of_credentials is None


def test_assertion_rejects_wrong_rp(device):
    ctap2 = Ctap2(device)
    _, attestation = make_credential(ctap2)
    cred_id = attestation.auth_data.credential_data.credential_id
    with pytest.raises(CtapError) as error:
        ctap2.get_assertion("other.example", os.urandom(32), allow_list=[{"type": "public-key", "id": cred_id}])
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


def test_tampered_credential_id_is_rejected(device):
    ctap2 = Ctap2(device)
    _, attestation = make_credential(ctap2)
    cred_id = bytearray(attestation.auth_data.credential_data.credential_id)
    cred_id[10] ^= 0x01
    with pytest.raises(CtapError) as error:
        ctap2.get_assertion(RP["id"], os.urandom(32), allow_list=[{"type": "public-key", "id": bytes(cred_id)}])
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


def test_exclude_list(device):
    ctap2 = Ctap2(device)
    _, attestation = make_credential(ctap2)
    cred_id = attestation.auth_data.credential_data.credential_id
    with pytest.raises(CtapError) as error:
        make_credential(ctap2, exclude_list=[{"type": "public-key", "id": cred_id}])
    assert error.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED
    # The same ID for another RP is not ours there: registration proceeds.
    make_credential(ctap2, rp={"id": "other.example", "name": "Other"}, exclude_list=[{"type": "public-key", "id": cred_id}])


def test_unsupported_algorithm(device):
    ctap2 = Ctap2(device)
    with pytest.raises(CtapError) as error:
        ctap2.make_credential(os.urandom(32), RP, USER, [{"type": "public-key", "alg": -8}])
    assert error.value.code == CtapError.ERR.UNSUPPORTED_ALGORITHM


def test_missing_parameter(device):
    ctap2 = Ctap2(device)
    with pytest.raises(CtapError) as error:
        ctap2.send_cbor(Ctap2.CMD.MAKE_CREDENTIAL, {1: os.urandom(32), 2: RP})
    assert error.value.code == CtapError.ERR.MISSING_PARAMETER


def test_up_false_is_invalid_option(device):
    ctap2 = Ctap2(device)
    with pytest.raises(CtapError) as error:
        make_credential(ctap2, options={"up": False})
    assert error.value.code == CtapError.ERR.INVALID_OPTION


def test_resident_credentials_and_next_assertion(device):
    ctap2 = Ctap2(device)
    users = [
        {"id": b"id-1", "name": "first", "displayName": "First User"},
        {"id": b"id-2", "name": "second", "displayName": "Second User"},
        {"id": b"id-3", "name": "third", "displayName": "Third User"},
    ]
    creds = {}
    for user in users:
        _, attestation = make_credential(ctap2, user=user, options={"rk": True})
        creds[user["id"]] = attestation.auth_data.credential_data

    client_data_hash = os.urandom(32)
    first = ctap2.get_assertion(RP["id"], client_data_hash)
    assert first.number_of_credentials == 3
    assertions = [first] + [ctap2.get_next_assertion() for _ in range(2)]
    # Newest first, and every assertion verifies with its own key.
    assert [a.user["id"] for a in assertions] == [b"id-3", b"id-2", b"id-1"]
    for assertion in assertions:
        assertion.verify(client_data_hash, creds[assertion.user["id"]].public_key)
        assert assertion.credential["id"] == creds[assertion.user["id"]].credential_id
    # Without user verification only the user id is disclosed when there are several accounts.
    assert "name" not in first.user
    # No more assertions
    with pytest.raises(CtapError) as error:
        ctap2.get_next_assertion()
    assert error.value.code == CtapError.ERR.NOT_ALLOWED
    assert ctap2.get_info().remaining_disc_creds == 32 - 3


def test_resident_credential_replaces_same_user(device):
    ctap2 = Ctap2(device)
    make_credential(ctap2, options={"rk": True})
    _, second = make_credential(ctap2, options={"rk": True})
    assertion = ctap2.get_assertion(RP["id"], os.urandom(32))
    assert assertion.number_of_credentials is None
    assert assertion.credential["id"] == second.auth_data.credential_data.credential_id
    # A single account: the names are included.
    assert assertion.user["name"] == "alice"
    assert assertion.user["displayName"] == "Alice"


def test_resident_credential_works_in_allow_list_and_survives_restart(make_authenticator):
    authenticator = make_authenticator()
    ctap2 = Ctap2(authenticator.device)
    _, attestation = make_credential(ctap2, options={"rk": True})
    cred = attestation.auth_data.credential_data
    authenticator.close()

    restarted = make_authenticator()
    ctap2 = Ctap2(restarted.device)
    client_data_hash = os.urandom(32)
    assertion = ctap2.get_assertion(RP["id"], client_data_hash, allow_list=[{"type": "public-key", "id": cred.credential_id}])
    assertion.verify(client_data_hash, cred.public_key)
    assert assertion.user["id"] == USER["id"]
    assert ctap2.get_assertion(RP["id"], os.urandom(32)).credential["id"] == cred.credential_id


def test_reset(device):
    ctap2 = Ctap2(device)
    _, attestation = make_credential(ctap2, options={"rk": True})
    cred = attestation.auth_data.credential_data
    ctap2.reset()
    with pytest.raises(CtapError) as error:
        ctap2.get_assertion(RP["id"], os.urandom(32))
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS
    # Keys derive from the master secret, which the reset replaced.
    with pytest.raises(CtapError) as error:
        ctap2.get_assertion(RP["id"], os.urandom(32), allow_list=[{"type": "public-key", "id": cred.credential_id}])
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS
    assert ctap2.get_info().remaining_disc_creds == 32


def test_selection(device):
    Ctap2(device).selection()


def test_user_presence_denied(make_authenticator):
    ctap2 = Ctap2(make_authenticator(up="deny").device)
    with pytest.raises(CtapError) as error:
        make_credential(ctap2)
    assert error.value.code == CtapError.ERR.OPERATION_DENIED


def test_user_presence_timeout(make_authenticator):
    ctap2 = Ctap2(make_authenticator(up="timeout", up_timeout_ms=700).device)
    keepalives = []
    with pytest.raises(CtapError) as error:
        ctap2.make_credential(os.urandom(32), RP, USER, KEY_PARAMS, on_keepalive=keepalives.append)
    assert error.value.code == CtapError.ERR.USER_ACTION_TIMEOUT
    assert 2 in keepalives  # STATUS_UPNEEDED was reported while waiting


def test_cancel_while_waiting(make_authenticator):
    import threading
    from fido2 import cbor
    from fido2.ctap2.base import args as ctap_args
    authenticator = make_authenticator(up="timeout", up_timeout_ms=5000)
    device = authenticator.device
    event = threading.Event()
    threading.Timer(0.3, event.set).start()
    # device.call() sends CTAPHID_CANCEL when the event fires and returns the status the key answers with.
    response = device.call(CTAPHID.CBOR, bytes([Ctap2.CMD.MAKE_CREDENTIAL]) + cbor.encode(ctap_args(os.urandom(32), RP, USER, KEY_PARAMS)), event=event)
    assert response == bytes([CtapError.ERR.KEEPALIVE_CANCEL])
    # The authenticator is usable again right away.
    assert Ctap2(device).get_info().aaguid == AAGUID


def test_hmac_secret_extension(device):
    from fido2.ctap2 import ClientPin
    ctap2 = Ctap2(device)
    _, attestation = make_credential(ctap2, extensions={"hmac-secret": True})
    assert attestation.auth_data.extensions == {"hmac-secret": True}
    cred_id = attestation.auth_data.credential_data.credential_id

    client_pin = ClientPin(ctap2)
    key_agreement, shared_secret = client_pin._get_shared_secret()
    protocol = client_pin.protocol
    salt1, salt2 = os.urandom(32), os.urandom(32)

    def get_outputs(salts):
        salt_enc = protocol.encrypt(shared_secret, salts)
        salt_auth = protocol.authenticate(shared_secret, salt_enc)
        assertion = ctap2.get_assertion(
            RP["id"],
            os.urandom(32),
            allow_list=[{"type": "public-key", "id": cred_id}],
            extensions={"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: protocol.VERSION}},
        )
        assert assertion.auth_data.flags & AuthenticatorData.FLAG.ED
        return protocol.decrypt(shared_secret, assertion.auth_data.extensions["hmac-secret"])

    one = get_outputs(salt1)
    assert len(one) == 32
    two = get_outputs(salt1 + salt2)
    assert len(two) == 64
    assert two[:32] == one  # deterministic per credential and salt
    assert two[32:] != one
    assert get_outputs(salt2) == two[32:]


def test_cred_protect_uv_required_hidden_without_uv(device):
    ctap2 = Ctap2(device)
    _, attestation = make_credential(ctap2, extensions={"credProtect": 3}, options={"rk": True})
    assert attestation.auth_data.extensions == {"credProtect": 3}
    cred_id = attestation.auth_data.credential_data.credential_id
    with pytest.raises(CtapError) as error:
        ctap2.get_assertion(RP["id"], os.urandom(32), allow_list=[{"type": "public-key", "id": cred_id}])
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS
    with pytest.raises(CtapError) as error:
        ctap2.get_assertion(RP["id"], os.urandom(32))
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


def test_cred_protect_level_2_requires_allow_list(device):
    ctap2 = Ctap2(device)
    _, attestation = make_credential(ctap2, extensions={"credProtect": 2}, options={"rk": True})
    cred_id = attestation.auth_data.credential_data.credential_id
    with pytest.raises(CtapError) as error:
        ctap2.get_assertion(RP["id"], os.urandom(32))
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS
    ctap2.get_assertion(RP["id"], os.urandom(32), allow_list=[{"type": "public-key", "id": cred_id}])
