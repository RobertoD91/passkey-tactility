# SPDX-License-Identifier: Apache-2.0
"""U2F (CTAP1) over CTAPHID_MSG, and interoperability of U2F key handles with CTAP2."""
import hashlib
import os
import time

import pytest
from cryptography import x509
from fido2.ctap1 import APDU, ApduError, Ctap1
from fido2.ctap2 import Ctap2


def with_presence(operation):
    """U2F clients poll while the authenticator answers 'conditions not satisfied' until the user touches it."""
    deadline = time.monotonic() + 5
    while True:
        try:
            return operation()
        except ApduError as error:
            if error.code != APDU.USE_NOT_SATISFIED or time.monotonic() > deadline:
                raise
            time.sleep(0.05)


def register_with_presence(ctap1, client_param, app_param):
    return with_presence(lambda: ctap1.register(client_param, app_param))


def authenticate_with_presence(ctap1, client_param, app_param, key_handle):
    return with_presence(lambda: ctap1.authenticate(client_param, app_param, key_handle))


def test_version(device):
    assert Ctap1(device).get_version() == "U2F_V2"


def test_register_and_authenticate(device):
    ctap1 = Ctap1(device)
    app_param = hashlib.sha256(b"https://example.com").digest()
    client_param = os.urandom(32)
    # Without a touch yet, register asks for one; the client polls until the user confirms.
    with pytest.raises(ApduError) as error:
        ctap1.register(client_param, app_param)
    assert error.value.code == APDU.USE_NOT_SATISFIED
    registration = register_with_presence(ctap1, client_param, app_param)
    registration.verify(app_param, client_param)
    assert len(registration.key_handle) == 50
    certificate = x509.load_der_x509_certificate(registration.certificate)
    assert certificate.subject.rfc4514_string() == "CN=Tactility Passkey"
    assert certificate.version == x509.Version.v3

    # check-only reports a valid key handle with "conditions not satisfied"
    with pytest.raises(ApduError) as error:
        ctap1.authenticate(client_param, app_param, registration.key_handle, check_only=True)
    assert error.value.code == APDU.USE_NOT_SATISFIED

    client_param = os.urandom(32)
    signature = authenticate_with_presence(ctap1, client_param, app_param, registration.key_handle)
    signature.verify(app_param, client_param, registration.public_key)
    assert signature.user_presence == 1
    counter = signature.counter
    assert authenticate_with_presence(ctap1, os.urandom(32), app_param, registration.key_handle).counter == counter + 1

    # wrong application parameter or tampered handle
    with pytest.raises(ApduError) as error:
        ctap1.authenticate(client_param, hashlib.sha256(b"https://other.example").digest(), registration.key_handle)
    assert error.value.code == APDU.WRONG_DATA
    bad_handle = bytearray(registration.key_handle)
    bad_handle[-1] ^= 0xFF
    with pytest.raises(ApduError) as error:
        ctap1.authenticate(client_param, app_param, bytes(bad_handle), check_only=True)
    assert error.value.code == APDU.WRONG_DATA


def test_unknown_instruction(device):
    with pytest.raises(ApduError) as error:
        Ctap1(device).send_apdu(ins=0x42)
    assert error.value.code == 0x6D00


def test_u2f_handle_usable_through_ctap2(device):
    ctap1 = Ctap1(device)
    rp_id = "example.com"
    app_param = hashlib.sha256(rp_id.encode()).digest()
    registration = register_with_presence(ctap1, os.urandom(32), app_param)
    ctap2 = Ctap2(device)
    client_data_hash = os.urandom(32)
    assertion = ctap2.get_assertion(rp_id, client_data_hash, allow_list=[{"type": "public-key", "id": registration.key_handle}])
    assert assertion.auth_data.rp_id_hash == app_param
    from fido2.cose import ES256
    public_key = ES256.from_ctap1(registration.public_key)
    assertion.verify(client_data_hash, public_key)


def test_ctap2_credential_usable_through_u2f(device):
    from test_ctap2 import KEY_PARAMS, RP, USER
    ctap2 = Ctap2(device)
    attestation = ctap2.make_credential(os.urandom(32), RP, USER, KEY_PARAMS)
    cred = attestation.auth_data.credential_data
    ctap1 = Ctap1(device)
    app_param = hashlib.sha256(RP["id"].encode()).digest()
    client_param = os.urandom(32)
    signature = authenticate_with_presence(ctap1, client_param, app_param, cred.credential_id)
    public_key = b"\x04" + cred.public_key[-2] + cred.public_key[-3]
    signature.verify(app_param, client_param, public_key)
