import pytest

from app import trust
from app.trust import Certificate, configure_ca_trust, extract_certificates


def test_ca_trust_is_optional_when_not_configured(monkeypatch):
    monkeypatch.delenv("CORPORATE_CA_BUNDLE", raising=False)
    assert configure_ca_trust().enabled is False


def test_invalid_ca_bundle_is_rejected():
    with pytest.raises(RuntimeError, match="contains no PEM certificates"):
        extract_certificates(b"not a certificate")


def test_missing_configured_ca_bundle_is_rejected(tmp_path):
    with pytest.raises(RuntimeError, match="was not found"):
        configure_ca_trust(corporate_bundle_path=str(tmp_path / "missing.pem"))


def test_ca_bundle_configures_python_and_chromium_trust(tmp_path, monkeypatch):
    source = tmp_path / "corporate-ca.pem"
    source.write_bytes(b"test certificate bundle")
    runtime = tmp_path / "runtime-ca.pem"
    nss_database = tmp_path / "nssdb"
    certificate = Certificate(
        pem=b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
        fingerprint="a" * 64,
    )
    certutil_calls = []

    monkeypatch.setattr(trust, "extract_certificates", lambda _bundle: [certificate])
    monkeypatch.setattr(trust, "_system_ca_bundle", lambda: None)
    monkeypatch.setattr(trust, "_is_self_signed", lambda _path: True)
    monkeypatch.setattr(trust.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(
        trust,
        "_run_certutil",
        lambda arguments, check=True: certutil_calls.append((arguments, check)),
    )

    status = configure_ca_trust(
        corporate_bundle_path=str(source),
        runtime_bundle_path=str(runtime),
        nss_database_path=str(nss_database),
    )

    assert status.enabled is True
    assert status.certificates == 1
    assert status.roots == 1
    assert status.intermediates == 0
    assert runtime.read_bytes() == b"test certificate bundle\n"
    assert trust.os.environ["SSL_CERT_FILE"] == str(runtime)
    assert trust.os.environ["REQUESTS_CA_BUNDLE"] == str(runtime)
    assert trust.os.environ["CURL_CA_BUNDLE"] == str(runtime)
    assert certutil_calls[0][0][-2:] == ["-N", "--empty-password"]
    assert certutil_calls[-1][0][0:6] == [
        "-d", f"sql:{nss_database}", "-A", "-t", "C,,", "-n",
    ]
