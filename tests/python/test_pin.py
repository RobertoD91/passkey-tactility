# SPDX-License-Identifier: Apache-2.0
"""authenticatorClientPIN with both PIN protocols, and PIN-protected operations."""
import os

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2, PinProtocolV1, PinProtocolV2
from fido2.webauthn import AuthenticatorData

from test_ctap2 import KEY_PARAMS, RP, USER

PIN = "1234"


@pytest.fixture(params=[PinProtocolV1, PinProtocolV2], ids=["protocol1", "protocol2"])
def protocol(request):
    return request.param()


def test_set_and_use_pin(device, protocol):
    ctap2 = Ctap2(device)
    client_pin = ClientPin(ctap2, protocol)
    assert client_pin.get_pin_retries() == (8, False)
    client_pin.set_pin(PIN)
    assert ctap2.get_info().options["clientPin"] is True

    # A second setPIN is refused.
    with pytest.raises(CtapError) as error:
        client_pin.set_pin("9999")
    assert error.value.code == CtapError.ERR.PIN_AUTH_INVALID

    token = client_pin.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION, RP["id"])
    client_data_hash = os.urandom(32)
    attestation = ctap2.make_credential(
        client_data_hash, RP, USER, KEY_PARAMS, options={"rk": True},
        pin_uv_param=protocol.authenticate(token, client_data_hash), pin_uv_protocol=protocol.VERSION,
    )
    assert attestation.auth_data.flags & AuthenticatorData.FLAG.UV

    client_data_hash = os.urandom(32)
    assertion = ctap2.get_assertion(
        RP["id"], client_data_hash,
        pin_uv_param=protocol.authenticate(token, client_data_hash), pin_uv_protocol=protocol.VERSION,
    )
    assert assertion.auth_data.flags & AuthenticatorData.FLAG.UV
    assertion.verify(client_data_hash, attestation.auth_data.credential_data.public_key)
    # With user verification the account names are returned.
    assert assertion.user["name"] == "alice"


def test_wrong_pin_and_retries(device, protocol):
    ctap2 = Ctap2(device)
    client_pin = ClientPin(ctap2, protocol)
    client_pin.set_pin(PIN)
    with pytest.raises(CtapError) as error:
        client_pin.get_pin_token("0000")
    assert error.value.code == CtapError.ERR.PIN_INVALID
    assert client_pin.get_pin_retries() == (7, False)
    with pytest.raises(CtapError) as error:
        client_pin.get_pin_token("0000")
    assert error.value.code == CtapError.ERR.PIN_INVALID
    with pytest.raises(CtapError) as error:
        client_pin.get_pin_token("0000")
    assert error.value.code == CtapError.ERR.PIN_AUTH_BLOCKED
    assert client_pin.get_pin_retries() == (5, True)
    # Blocked until a power cycle, even with the right PIN.
    with pytest.raises(CtapError) as error:
        client_pin.get_pin_token(PIN)
    assert error.value.code == CtapError.ERR.PIN_AUTH_BLOCKED


def test_retries_restore_after_power_cycle(make_authenticator, protocol):
    authenticator = make_authenticator()
    ctap2 = Ctap2(authenticator.device)
    client_pin = ClientPin(ctap2, protocol)
    client_pin.set_pin(PIN)
    for _ in range(3):
        with pytest.raises(CtapError):
            client_pin.get_pin_token("0000")
    authenticator.close()

    restarted = make_authenticator()
    ctap2 = Ctap2(restarted.device)
    client_pin = ClientPin(ctap2, protocol)
    assert client_pin.get_pin_retries() == (5, False)
    client_pin.get_pin_token(PIN)
    assert client_pin.get_pin_retries() == (8, False)


def test_change_pin(device, protocol):
    ctap2 = Ctap2(device)
    client_pin = ClientPin(ctap2, protocol)
    client_pin.set_pin(PIN)
    client_pin.change_pin(PIN, "secret-pin")
    with pytest.raises(CtapError) as error:
        client_pin.get_pin_token(PIN)
    assert error.value.code == CtapError.ERR.PIN_INVALID
    client_pin.get_pin_token("secret-pin")
    with pytest.raises(CtapError) as error:
        client_pin.change_pin("wrong", "another")
    assert error.value.code == CtapError.ERR.PIN_INVALID


def test_pin_policy(device, protocol):
    ctap2 = Ctap2(device)
    client_pin = ClientPin(ctap2, protocol)

    def raw_set_pin(padded_pin):
        # python-fido2 validates the PIN length itself, so the policy is exercised with raw subcommands.
        key_agreement, shared_secret = client_pin._get_shared_secret()
        pin_enc = protocol.encrypt(shared_secret, padded_pin)
        ctap2.client_pin(protocol.VERSION, ClientPin.CMD.SET_PIN, key_agreement=key_agreement,
                         new_pin_enc=pin_enc, pin_uv_param=protocol.authenticate(shared_secret, pin_enc))

    with pytest.raises(CtapError) as error:
        raw_set_pin(b"123".ljust(64, b"\0"))
    assert error.value.code == CtapError.ERR.PIN_POLICY_VIOLATION
    with pytest.raises(CtapError) as error:
        raw_set_pin(b"x" * 64)
    assert error.value.code == CtapError.ERR.PIN_POLICY_VIOLATION
    with pytest.raises(CtapError) as error:
        raw_set_pin(b"1234".ljust(32, b"\0"))  # wrong padding length
    assert error.value.code == CtapError.ERR.INVALID_PARAMETER
    client_pin.set_pin("çàé€")  # 4 code points, 9 bytes
    client_pin.get_pin_token("çàé€")


def test_pin_required_for_resident_credential(device, protocol):
    ctap2 = Ctap2(device)
    ClientPin(ctap2, protocol).set_pin(PIN)
    with pytest.raises(CtapError) as error:
        ctap2.make_credential(os.urandom(32), RP, USER, KEY_PARAMS, options={"rk": True})
    assert error.value.code == CtapError.ERR.PUAT_REQUIRED
    # Non-discoverable credentials don't need the PIN (makeCredUvNotRqd).
    attestation = ctap2.make_credential(os.urandom(32), RP, USER, KEY_PARAMS)
    assert not attestation.auth_data.flags & AuthenticatorData.FLAG.UV


def test_pin_probe_and_bad_token(device, protocol):
    ctap2 = Ctap2(device)
    with pytest.raises(CtapError) as error:
        ctap2.make_credential(os.urandom(32), RP, USER, KEY_PARAMS, pin_uv_param=b"", pin_uv_protocol=protocol.VERSION)
    assert error.value.code == CtapError.ERR.PIN_NOT_SET
    ClientPin(ctap2, protocol).set_pin(PIN)
    with pytest.raises(CtapError) as error:
        ctap2.make_credential(os.urandom(32), RP, USER, KEY_PARAMS, pin_uv_param=b"", pin_uv_protocol=protocol.VERSION)
    assert error.value.code == CtapError.ERR.PIN_INVALID
    with pytest.raises(CtapError) as error:
        ctap2.make_credential(os.urandom(32), RP, USER, KEY_PARAMS, pin_uv_param=os.urandom(16), pin_uv_protocol=protocol.VERSION)
    assert error.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_token_permissions_and_rp_binding(device, protocol):
    ctap2 = Ctap2(device)
    client_pin = ClientPin(ctap2, protocol)
    client_pin.set_pin(PIN)
    token = client_pin.get_pin_token(PIN, ClientPin.PERMISSION.GET_ASSERTION, "other.example")
    client_data_hash = os.urandom(32)
    with pytest.raises(CtapError) as error:
        ctap2.make_credential(
            client_data_hash, RP, USER, KEY_PARAMS,
            pin_uv_param=protocol.authenticate(token, client_data_hash), pin_uv_protocol=protocol.VERSION,
        )
    assert error.value.code == CtapError.ERR.PIN_AUTH_INVALID
    token = client_pin.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, "other.example")
    with pytest.raises(CtapError) as error:
        ctap2.make_credential(
            client_data_hash, RP, USER, KEY_PARAMS,
            pin_uv_param=protocol.authenticate(token, client_data_hash), pin_uv_protocol=protocol.VERSION,
        )
    assert error.value.code == CtapError.ERR.PIN_AUTH_INVALID
    with pytest.raises(CtapError) as error:
        client_pin.get_pin_token(PIN, ClientPin.PERMISSION.BIO_ENROLL)
    assert error.value.code == CtapError.ERR.UNAUTHORIZED_PERMISSION


def test_reset_clears_pin(device, protocol):
    ctap2 = Ctap2(device)
    ClientPin(ctap2, protocol).set_pin(PIN)
    ctap2.reset()
    assert ctap2.get_info().options["clientPin"] is False
    ClientPin(ctap2, protocol).set_pin("4321")
