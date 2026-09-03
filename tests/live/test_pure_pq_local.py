# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Real-CLI coverage for OpenSSL pure post-quantum TLS groups."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.live.test_live_targets import _openssl_path


def _reserve_port() -> int:
    """Ask the kernel for an unused loopback TCP port."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_server(process: subprocess.Popen[bytes], port: int) -> None:
    """Wait until the local OpenSSL server accepts TCP connections."""
    for _ in range(100):
        if process.poll() is not None:
            pytest.fail(f"openssl s_server exited early with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    pytest.fail("openssl s_server did not accept connections within 5 seconds")


def _generate_certificate(openssl_path: str, directory: Path) -> tuple[Path, Path]:
    """Generate an ephemeral Ed25519 certificate for the local TLS endpoint."""
    certificate = directory / "server.crt"
    private_key = directory / "server.key"
    subprocess.run(  # noqa: S603 -- capability-validated OpenSSL, list argv, shell disabled.
        [
            openssl_path,
            "req",
            "-x509",
            "-newkey",
            "ed25519",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
        shell=False,
        timeout=15,
    )
    return certificate, private_key


@pytest.mark.parametrize(
    ("group", "nist_level"),
    [("MLKEM512", 1), ("MLKEM768", 3), ("MLKEM1024", 5)],
)
def test_real_cli_detects_pure_pq_only_endpoint(
    tmp_path: Path,
    group: str,
    nist_level: int,
) -> None:
    """A pure-ML-KEM server must not collapse to the unknown/dead-port result (#521)."""
    openssl_path = _openssl_path()
    certificate, private_key = _generate_certificate(openssl_path, tmp_path)
    port = _reserve_port()
    server = subprocess.Popen(  # noqa: S603 -- capability-validated OpenSSL, fixed argv.
        [
            openssl_path,
            "s_server",
            "-accept",
            f"127.0.0.1:{port}",
            "-cert",
            str(certificate),
            "-key",
            str(private_key),
            "-groups",
            group,
            "-www",
            "-quiet",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    try:
        _wait_for_server(server, port)
        completed = subprocess.run(  # noqa: S603 -- current interpreter, fixed module/argv.
            [
                sys.executable,
                "-m",
                "qureddy",
                "scan",
                "tls",
                f"127.0.0.1:{port}",
                "--openssl",
                openssl_path,
                "--timeout",
                "3",
                "--format",
                "json",
            ],
            check=False,
            capture_output=True,
            shell=False,
            text=True,
            timeout=60,
        )
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    interpretation = payload["summary"]["interpretation"]
    assert payload["scan"]["status"] == "completed"
    assert payload["summary"]["readiness"] == "quantum_safe"
    assert interpretation["axes"]["pqc_support"] == "pure_pq_observed"
    assert interpretation["axes"]["key_exchange"] == "pure_pq"
    assert interpretation["hndl_exposure"] == "protected"
    assert interpretation["headline"] == "Pure post-quantum key exchange was observed."
    assert interpretation["reason_codes"] == ["pure_pq_observed"]
    pure_finding = next(
        finding for finding in payload["findings"] if finding["rule_id"] == "tls.pq.negotiated_pure"
    )
    assert pure_finding["algorithm"] == group
    assert pure_finding["nist_quantum_security_level"] == nist_level
    assert any(
        evidence.get("probe_role") == "pure_pq_coverage"
        and evidence.get("negotiated_group") == group
        for evidence in payload["evidence"]
    )
