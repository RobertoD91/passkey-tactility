# SPDX-License-Identifier: Apache-2.0
"""Drives the host build of the authenticator through python-fido2's own CTAPHID framing.

The authenticator process reads 64-byte CTAPHID packets from stdin and writes them to stdout, so
`CtapHidDevice` sees exactly what it would see over USB.
"""
import os
import subprocess

from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor

PACKET_SIZE = 64


class PipeConnection(CtapHidConnection):
    def __init__(self, process: subprocess.Popen):
        self._process = process

    def write_packet(self, data: bytes) -> None:
        assert len(data) == PACKET_SIZE
        self._process.stdin.write(data)
        self._process.stdin.flush()

    def read_packet(self) -> bytes:
        data = b""
        while len(data) < PACKET_SIZE:
            chunk = self._process.stdout.read(PACKET_SIZE - len(data))
            if not chunk:
                raise IOError("authenticator process closed its output")
            data += chunk
        return data

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.stdin.close()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()


class Authenticator:
    """A running authenticator process plus the CtapHidDevice talking to it."""

    def __init__(self, binary: str, store_path: str, up: str = "confirm", up_delay_ms: int = 20, up_timeout_ms: int | None = None, log_path: str | None = None):
        env = dict(os.environ)
        env["PASSKEY_STORE"] = store_path
        env["PASSKEY_UP"] = up
        env["PASSKEY_UP_DELAY_MS"] = str(up_delay_ms)
        if up_timeout_ms is not None:
            env["PASSKEY_UP_TIMEOUT_MS"] = str(up_timeout_ms)
        self._log = open(log_path, "ab") if log_path else subprocess.DEVNULL
        self.process = subprocess.Popen(
            [binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._log,
            env=env,
            bufsize=0,
        )
        descriptor = HidDescriptor("pipe", 0x303A, 0x4009, PACKET_SIZE, PACKET_SIZE, "Tactility FIDO", "1")
        self.connection = PipeConnection(self.process)
        self.device = CtapHidDevice(descriptor, self.connection)

    def close(self) -> None:
        self.connection.close()
        if self._log is not subprocess.DEVNULL:
            self._log.close()
