# SPDX-License-Identifier: Apache-2.0
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipe_device import Authenticator  # noqa: E402

HOST_BINARY = os.environ.get(
    "PASSKEY_HOST_BINARY",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "host", "build", "passkey-host"),
)


@pytest.fixture
def store_path(tmp_path):
    return str(tmp_path / "store.bin")


@pytest.fixture
def make_authenticator(store_path, tmp_path):
    """Factory: start an authenticator process on the test's own state file."""
    started = []

    def factory(**kwargs):
        kwargs.setdefault("log_path", str(tmp_path / "authenticator.log"))
        authenticator = Authenticator(HOST_BINARY, store_path, **kwargs)
        started.append(authenticator)
        return authenticator

    yield factory
    for authenticator in started:
        authenticator.close()


@pytest.fixture
def authenticator(make_authenticator):
    return make_authenticator()


@pytest.fixture
def device(authenticator):
    return authenticator.device
