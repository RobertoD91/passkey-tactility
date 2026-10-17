# SPDX-License-Identifier: Apache-2.0
"""End-to-end WebAuthn flows through python-fido2's Fido2Client, as a browser would run them."""
import os

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.server import Fido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

PIN = "1234"


class Interaction(UserInteraction):
    def prompt_up(self):
        pass

    def request_pin(self, permissions, rp_id):
        return PIN

    def request_uv(self, permissions, rp_id):
        return True


def make_client(device):
    collector = DefaultClientDataCollector("https://example.com")
    return Fido2Client(device, collector, user_interaction=Interaction())


def test_webauthn_registration_and_authentication(device):
    client = make_client(device)
    server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"), attestation="direct")
    user = PublicKeyCredentialUserEntity(id=b"user", name="alice", display_name="Alice")

    create_options, state = server.register_begin(user, user_verification=UserVerificationRequirement.DISCOURAGED)
    result = client.make_credential(create_options["publicKey"])
    auth_data = server.register_complete(state, result)
    assert auth_data.credential_data is not None

    request_options, state = server.authenticate_begin([auth_data.credential_data], user_verification=UserVerificationRequirement.DISCOURAGED)
    assertions = client.get_assertion(request_options["publicKey"])
    server.authenticate_complete(state, [auth_data.credential_data], assertions.get_response(0))


def test_webauthn_discoverable_with_pin_and_prf(device):
    from fido2.ctap2 import ClientPin, Ctap2
    ClientPin(Ctap2(device)).set_pin(PIN)
    client = make_client(device)
    server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"))
    user = PublicKeyCredentialUserEntity(id=b"user", name="alice", display_name="Alice")

    create_options, state = server.register_begin(
        user, resident_key_requirement=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED,
    )
    options = dict(create_options["publicKey"])
    options["extensions"] = {"prf": {}}
    result = client.make_credential(options)
    assert result.client_extension_results.get("prf", {}).get("enabled") is True
    auth_data = server.register_complete(state, result)
    assert auth_data.is_user_verified()

    request_options, state = server.authenticate_begin(user_verification=UserVerificationRequirement.REQUIRED)
    salt = os.urandom(32)
    options = dict(request_options["publicKey"])
    options["extensions"] = {"prf": {"eval": {"first": salt}}}
    assertions = client.get_assertion(options)
    response = assertions.get_response(0)
    first = websafe_decode(response.client_extension_results["prf"]["results"]["first"])
    assert len(first) == 32
    server.authenticate_complete(state, [auth_data.credential_data], response)
    assert response.response.user_handle == b"user"

    # Same salt, same secret
    assertions = client.get_assertion(options)
    assert websafe_decode(assertions.get_response(0).client_extension_results["prf"]["results"]["first"]) == first
