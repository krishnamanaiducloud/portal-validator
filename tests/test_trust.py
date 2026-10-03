import json
import os
from pathlib import Path

import pytest

from app import trust
from app.trust import Certificate, bootstrap_trust, extract_certificates, inspect_trust_status


def test_invalid_and_private_key_ca_inputs_are_rejected():
    with pytest.raises(RuntimeError, match="contains no PEM certificates"):
        extract_certificates(b"not a certificate")
    with pytest.raises(RuntimeError, match="must not contain private keys"):
        extract_certificates(b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----")


def test_missing_managed_bundle_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(trust.shutil, "which", lambda _command: "/usr/bin/certutil")
    with pytest.raises(RuntimeError, match="missing or empty"):
        bootstrap_trust(managed_bundle_path=str(tmp_path / "missing.pem"))


def _mock_certificate(fingerprint: str, marker: bytes) -> Certificate:
    return Certificate(
        pem=b"-----BEGIN CERTIFICATE-----\n" + marker + b"\n-----END CERTIFICATE-----\n",
        fingerprint=fingerprint * 64,
    )


def test_bootstrap_combines_ca_and_replaces_managed_nss_entries(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    additional = tmp_path / "enterprise.pem"
    managed.write_bytes(b"managed")
    additional.write_bytes(b"enterprise")
    runtime = tmp_path / "home" / "ca-bundle.crt"
    nss = tmp_path / "home" / "nssdb"
    state = tmp_path / "home" / "trust-status.json"
    managed_certificate = _mock_certificate("a", b"managed")
    enterprise_certificate = _mock_certificate("b", b"enterprise")
    calls = []

    def fake_extract(content):
        return [managed_certificate if content == b"managed" else enterprise_certificate]

    def fake_certutil(arguments, check=True):
        calls.append((arguments, check))
        if "-N" in arguments:
            nss.mkdir(parents=True, exist_ok=True)
            (nss / "cert9.db").touch()
        return None

    monkeypatch.setattr(trust, "extract_certificates", fake_extract)
    monkeypatch.setattr(trust, "_is_self_signed", lambda _path: True)
    monkeypatch.setattr(trust.shutil, "which", lambda _command: "/usr/bin/certutil")
    monkeypatch.setattr(trust, "_run_certutil", fake_certutil)

    status = bootstrap_trust(
        managed_bundle_path=str(managed),
        additional_files=[additional],
        optional_directories=[],
        runtime_bundle_path=str(runtime),
        nss_database_path=str(nss),
        state_path=str(state),
    )

    assert status.enabled is True
    assert status.certificates == 2
    assert status.roots == 1
    assert runtime.read_bytes() == managed_certificate.pem + enterprise_certificate.pem
    if os.name != "nt":
        assert runtime.stat().st_mode & 0o777 == 0o600
    assert any("-N" in arguments for arguments, _check in calls)
    delete = next(arguments for arguments, check in calls if "-D" in arguments and check is False)
    imported = next(arguments for arguments, check in calls if "-A" in arguments and check is True)
    assert delete[delete.index("-n") + 1] == imported[imported.index("-n") + 1]
    assert imported[imported.index("-t") + 1] == "C,,"

    first_import_count = sum("-A" in arguments for arguments, _check in calls)
    bootstrap_trust(
        managed_bundle_path=str(managed),
        additional_files=[additional],
        optional_directories=[],
        runtime_bundle_path=str(runtime),
        nss_database_path=str(nss),
        state_path=str(state),
    )
    assert sum("-A" in arguments for arguments, _check in calls) == first_import_count + 1
    assert len(json.loads(state.read_text())["nss_nicknames"]) == 1


def test_optional_ca_directory_can_be_absent(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    managed.write_bytes(b"managed")
    certificate = _mock_certificate("a", b"managed")
    monkeypatch.setattr(trust, "extract_certificates", lambda _content: [certificate])
    monkeypatch.setattr(trust.shutil, "which", lambda _command: "/usr/bin/certutil")
    monkeypatch.setattr(trust, "_run_certutil", lambda *_args, **_kwargs: None)
    status = bootstrap_trust(
        managed_bundle_path=str(managed),
        additional_files=[],
        optional_directories=[tmp_path / "not-mounted"],
        runtime_bundle_path=str(tmp_path / "runtime.pem"),
        nss_database_path=str(tmp_path / "nss"),
        state_path=str(tmp_path / "status.json"),
    )
    assert status.certificates == 1
    assert status.roots == 0


def test_status_inspection_does_not_mutate_trust(tmp_path, monkeypatch):
    status_path = tmp_path / "trust-status.json"
    status_path.write_text(json.dumps({
        "enabled": True,
        "certificates": 3,
        "roots": 1,
        "intermediates": 1,
        "runtime_bundle": "/tmp/ca.pem",
    }))
    monkeypatch.setenv("PORTAL_VALIDATOR_TRUST_STATUS", str(status_path))
    assert inspect_trust_status() == trust.TrustStatus(True, 3, 1, 1, "/tmp/ca.pem")


def test_entrypoint_initializes_trust_once_before_exec():
    script = (Path(__file__).resolve().parents[1] / "container-entrypoint.sh").read_text()
    assert script.count("python -m app.trust initialize") == 1
    assert script.index("python -m app.trust initialize") < script.index('exec "$@"')
    assert "SSL_CERT_FILE" in script and "REQUESTS_CA_BUNDLE" in script and "CURL_CA_BUNDLE" in script
