from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger(__name__)
PEM_CERTIFICATE_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
MAX_BUNDLE_BYTES = 10 * 1024 * 1024
MAX_CERTIFICATES = 500
SYSTEM_CA_CANDIDATES = (
    Path("/etc/ssl/certs/ca-certificates.crt"),
    Path("/etc/ssl/cert.pem"),
    Path("/etc/pki/tls/certs/ca-bundle.crt"),
)


@dataclass(frozen=True)
class TrustStatus:
    enabled: bool
    certificates: int = 0
    roots: int = 0
    intermediates: int = 0


@dataclass(frozen=True)
class Certificate:
    pem: bytes
    fingerprint: str


def extract_certificates(bundle: bytes) -> list[Certificate]:
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise RuntimeError("Corporate CA bundle exceeds the 10 MiB limit")
    matches = PEM_CERTIFICATE_RE.findall(bundle)
    if not matches:
        raise RuntimeError("Corporate CA bundle contains no PEM certificates")
    if len(matches) > MAX_CERTIFICATES:
        raise RuntimeError("Corporate CA bundle contains too many certificates")

    certificates: list[Certificate] = []
    seen: set[str] = set()
    for match in matches:
        pem = match.strip() + b"\n"
        try:
            der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError("Corporate CA bundle contains an invalid PEM certificate") from exc
        fingerprint = hashlib.sha256(der).hexdigest()
        if fingerprint not in seen:
            certificates.append(Certificate(pem=pem, fingerprint=fingerprint))
            seen.add(fingerprint)
    return certificates


def _is_self_signed(certificate_path: Path) -> bool:
    try:
        details = ssl._ssl._test_decode_cert(str(certificate_path))  # type: ignore[attr-defined]
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError("Unable to decode a certificate from the corporate CA bundle") from exc
    return details.get("subject") == details.get("issuer")


def _system_ca_bundle() -> Path | None:
    return next((path for path in SYSTEM_CA_CANDIDATES if path.is_file()), None)


def _write_runtime_bundle(corporate_bundle: bytes, destination: Path) -> None:
    system_bundle = _system_ca_bundle()
    combined = bytearray()
    if system_bundle:
        combined.extend(system_bundle.read_bytes().rstrip())
        combined.extend(b"\n")
    combined.extend(corporate_bundle.strip())
    combined.extend(b"\n")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    temporary.write_bytes(combined)
    temporary.chmod(0o644)
    temporary.replace(destination)


def _run_certutil(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["certutil", *arguments],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def configure_ca_trust(
    corporate_bundle_path: str | None = None,
    runtime_bundle_path: str | None = None,
    nss_database_path: str | None = None,
) -> TrustStatus:
    configured_bundle = corporate_bundle_path or os.getenv("CORPORATE_CA_BUNDLE")
    if not configured_bundle:
        return TrustStatus(enabled=False)

    source = Path(configured_bundle)
    if not source.is_file():
        raise RuntimeError(f"Configured corporate CA bundle was not found: {source}")
    if not shutil.which("certutil"):
        raise RuntimeError("certutil is required to configure Chromium corporate CA trust")

    source_bytes = source.read_bytes()
    certificates = extract_certificates(source_bytes)
    runtime_bundle = Path(
        runtime_bundle_path
        or os.getenv("RUNTIME_CA_BUNDLE", "/tmp/portal-validator-ca-bundle.pem")
    )
    home = Path(os.getenv("HOME", "/tmp"))
    nss_database = Path(
        nss_database_path
        or os.getenv("CHROMIUM_NSS_DB", str(home / ".local/share/pki/nssdb"))
    )

    _write_runtime_bundle(source_bytes, runtime_bundle)
    for variable in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        os.environ[variable] = str(runtime_bundle)

    nss_database.mkdir(parents=True, exist_ok=True)
    database = f"sql:{nss_database}"
    if not (nss_database / "cert9.db").exists():
        _run_certutil(["-d", database, "-N", "--empty-password"])

    roots = 0
    intermediates = 0
    with tempfile.TemporaryDirectory(prefix="portal-validator-ca-", dir=runtime_bundle.parent) as directory:
        certificate_directory = Path(directory)
        for index, certificate in enumerate(certificates, start=1):
            certificate_path = certificate_directory / f"certificate-{index}.pem"
            certificate_path.write_bytes(certificate.pem)
            is_root = _is_self_signed(certificate_path)
            trust = "C,," if is_root else ",,"
            roots += int(is_root)
            intermediates += int(not is_root)
            nickname = f"portal-validator-{certificate.fingerprint[:16]}"
            _run_certutil(["-d", database, "-D", "-n", nickname], check=False)
            _run_certutil([
                "-d", database, "-A", "-t", trust, "-n", nickname,
                "-i", str(certificate_path),
            ])

    if roots == 0:
        raise RuntimeError("Corporate CA bundle must include at least one self-signed root CA")

    LOGGER.info(
        "Configured strict corporate CA trust with %d root(s) and %d intermediate(s)",
        roots,
        intermediates,
    )
    return TrustStatus(
        enabled=True,
        certificates=len(certificates),
        roots=roots,
        intermediates=intermediates,
    )
