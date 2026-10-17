# SPDX-License-Identifier: Apache-2.0
"""authenticatorCredentialManagement."""
import hashlib
import os

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2, PinProtocolV2
from fido2.webauthn import PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity

from test_ctap2 import KEY_PARAMS

PIN = "1234"


def setup(device):
    ctap2 = Ctap2(device)
    protocol = PinProtocolV2()
    client_pin = ClientPin(ctap2, protocol)
    client_pin.set_pin(PIN)
    creds = {}
    for rp_id, user_id, name in [("a.example", b"u1", "one"), ("a.example", b"u2", "two"), ("b.example", b"u3", "three")]:
        # A token is bound to one RP, like a browser would request it.
        token = client_pin.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp_id)
        client_data_hash = os.urandom(32)
        attestation = ctap2.make_credential(
            client_data_hash, {"id": rp_id, "name": rp_id.upper()}, {"id": user_id, "name": name, "displayName": name.title()},
            KEY_PARAMS, options={"rk": True},
            pin_uv_param=protocol.authenticate(token, client_data_hash), pin_uv_protocol=protocol.VERSION,
        )
        creds[user_id] = attestation.auth_data.credential_data
    token = client_pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    return ctap2, CredentialManagement(ctap2, protocol, token), creds


def test_metadata_and_enumeration(device):
    ctap2, management, creds = setup(device)
    metadata = management.get_metadata()
    assert metadata[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 3
    assert metadata[CredentialManagement.RESULT.MAX_REMAINING_COUNT] == 29

    rps = management.enumerate_rps()
    assert sorted(rp[CredentialManagement.RESULT.RP]["id"] for rp in rps) == ["a.example", "b.example"]
    assert rps[0][CredentialManagement.RESULT.TOTAL_RPS] == 2
    for rp in rps:
        assert rp[CredentialManagement.RESULT.RP_ID_HASH] == hashlib.sha256(rp[CredentialManagement.RESULT.RP]["id"].encode()).digest()
        assert rp[CredentialManagement.RESULT.RP]["name"] == rp[CredentialManagement.RESULT.RP]["id"].upper()

    listed = management.enumerate_creds(hashlib.sha256(b"a.example").digest())
    assert len(listed) == 2
    assert listed[0][CredentialManagement.RESULT.TOTAL_CREDENTIALS] == 2
    for entry in listed:
        user = entry[CredentialManagement.RESULT.USER]
        cred = creds[user["id"]]
        assert entry[CredentialManagement.RESULT.CREDENTIAL_ID]["id"] == cred.credential_id
        assert entry[CredentialManagement.RESULT.PUBLIC_KEY] == cred.public_key
        assert entry[CredentialManagement.RESULT.CRED_PROTECT] == 1
        assert user["displayName"] == user["name"].title()

    with pytest.raises(CtapError) as error:
        management.enumerate_creds_begin(hashlib.sha256(b"nobody.example").digest())
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


def test_delete_and_update(device):
    ctap2, management, creds = setup(device)
    management.delete_cred(PublicKeyCredentialDescriptor(type="public-key", id=creds[b"u1"].credential_id))
    assert management.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 2
    with pytest.raises(CtapError) as error:
        management.delete_cred(PublicKeyCredentialDescriptor(type="public-key", id=creds[b"u1"].credential_id))
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS
    with pytest.raises(CtapError) as error:
        ctap2.get_assertion("a.example", os.urandom(32), allow_list=[{"type": "public-key", "id": creds[b"u1"].credential_id}])
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS

    management.update_user_info(
        PublicKeyCredentialDescriptor(type="public-key", id=creds[b"u2"].credential_id),
        PublicKeyCredentialUserEntity(name="renamed", id=b"u2", display_name="Renamed User"),
    )
    listed = management.enumerate_creds(hashlib.sha256(b"a.example").digest())
    assert len(listed) == 1
    assert listed[0][CredentialManagement.RESULT.USER] == {"id": b"u2", "name": "renamed", "displayName": "Renamed User"}


def test_requires_token_with_permission(device):
    ctap2 = Ctap2(device)
    protocol = PinProtocolV2()
    client_pin = ClientPin(ctap2, protocol)
    client_pin.set_pin(PIN)
    token = client_pin.get_pin_token(PIN, ClientPin.PERMISSION.GET_ASSERTION)
    with pytest.raises(CtapError) as error:
        CredentialManagement(ctap2, protocol, token).get_metadata()
    assert error.value.code == CtapError.ERR.PIN_AUTH_INVALID
    with pytest.raises(CtapError) as error:
        ctap2.credential_mgmt(CredentialManagement.CMD.GET_CREDS_METADATA)
    assert error.value.code == CtapError.ERR.PUAT_REQUIRED


def test_preview_command(device):
    ctap2, management, creds = setup(device)
    protocol = PinProtocolV2()
    token = ClientPin(ctap2, protocol).get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    message = bytes([CredentialManagement.CMD.GET_CREDS_METADATA])
    response = ctap2.send_cbor(0x41, {1: CredentialManagement.CMD.GET_CREDS_METADATA, 3: protocol.VERSION, 4: protocol.authenticate(token, message)})
    assert response[1] == 3
