from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from app.logging_config import log_event


PEM_CERTIFICATE_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
MAX_BUNDLE_BYTES = 10 * 1024 * 1024
MAX_CERTIFICATES = 500
DEFAULT_MANAGED_BUNDLE = "/etc/portal-validator/certs/ca-bundle.crt"


@dataclass(frozen=True)
class TrustStatus:
    enabled: bool
    certificates: int = 0
    roots: int = 0
    intermediates: int = 0
    runtime_bundle: str | None = None


@dataclass(frozen=True)
class Certificate:
    pem: bytes
    fingerprint: str


def extract_certificates(bundle: bytes) -> list[Certificate]:
    if b"PRIVATE KEY" in bundle:
        raise RuntimeError("CA input must not contain private keys")
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise RuntimeError("CA input exceeds the 10 MiB limit")
    matches = PEM_CERTIFICATE_RE.findall(bundle)
    if not matches:
        raise RuntimeError("CA input contains no PEM certificates")
    if len(matches) > MAX_CERTIFICATES:
        raise RuntimeError("CA input contains too many certificates")

    certificates: list[Certificate] = []
    seen: set[str] = set()
    for match in matches:
        pem = match.strip() + b"\n"
        try:
            der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError("CA input contains an invalid PEM certificate") from exc
        fingerprint = hashlib.sha256(der).hexdigest()
        if fingerprint not in seen:
            certificates.append(Certificate(pem=pem, fingerprint=fingerprint))
            seen.add(fingerprint)
    return certificates


def _configured_paths(variable: str) -> list[Path]:
    return [Path(value) for value in os.getenv(variable, "").split(os.pathsep) if value]


def _load_required_file(path: Path) -> list[Certificate]:
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(f"Required CA file is missing or empty: {path}")
    try:
        return extract_certificates(path.read_bytes())
    except OSError as exc:
        raise RuntimeError(f"Required CA file is unreadable: {path}") from exc


def _additional_sources(
    additional_files: list[Path],
    optional_directories: list[Path],
) -> list[tuple[Path, list[Certificate]]]:
    sources = [(path, _load_required_file(path)) for path in additional_files]
    for directory in optional_directories:
        if not directory.exists():
            log_event(30, "OPTIONAL_CA_DIRECTORY_SKIPPED", path=str(directory))
            continue
        if not directory.is_dir():
            raise RuntimeError(f"Optional CA directory path is not a directory: {directory}")
        for path in sorted({*directory.glob("*.crt"), *directory.glob("*.pem")}):
            sources.append((path, _load_required_file(path)))
    return sources


def _atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(content)
    temporary.chmod(mode)
    temporary.replace(path)


def _run_certutil(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["certutil", *arguments],
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("certutil failed while initializing Chromium trust") from exc


def _is_self_signed(certificate_path: Path) -> bool:
    try:
        details = ssl._ssl._test_decode_cert(str(certificate_path))  # type: ignore[attr-defined]
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError("Unable to decode a configured enterprise CA certificate") from exc
    return details.get("subject") == details.get("issuer")


def _stable_nickname(source: Path, index: int) -> str:
    identity = hashlib.sha256(f"{source.resolve()}:{index}".encode()).hexdigest()[:20]
    return f"portal-validator-enterprise-{identity}"


def _read_previous_nicknames(state_path: Path) -> set[str]:
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return set()
    return {
        value for value in payload.get("nss_nicknames", [])
        if isinstance(value, str) and value.startswith("portal-validator-enterprise-")
    }


def bootstrap_trust(
    *,
    managed_bundle_path: str | None = None,
    additional_files: list[Path] | None = None,
    optional_directories: list[Path] | None = None,
    runtime_bundle_path: str | None = None,
    nss_database_path: str | None = None,
    state_path: str | None = None,
) -> TrustStatus:
    if not shutil.which("certutil"):
        raise RuntimeError("certutil is required to initialize Chromium enterprise trust")

    home = Path(os.environ.get("HOME") or "/tmp/portal-validator-home")
    managed_path = Path(
        managed_bundle_path
        or os.getenv("PORTAL_VALIDATOR_MANAGED_CA_BUNDLE", DEFAULT_MANAGED_BUNDLE)
    )
    runtime_path = Path(
        runtime_bundle_path
        or os.getenv("RUNTIME_CA_BUNDLE", str(home / ".portal-validator/ca-bundle.crt"))
    )
    nss_path = Path(
        nss_database_path
        or os.getenv("CHROMIUM_NSS_DB", str(home / ".local/share/pki/nssdb"))
    )
    status_path = Path(
        state_path
        or os.getenv("PORTAL_VALIDATOR_TRUST_STATUS", str(home / ".portal-validator/trust-status.json"))
    )
    required_additional = additional_files if additional_files is not None else _configured_paths(
        "PORTAL_VALIDATOR_ADDITIONAL_CA_FILES"
    )
    optional_dirs = optional_directories if optional_directories is not None else _configured_paths(
        "PORTAL_VALIDATOR_OPTIONAL_CA_DIRS"
    )

    managed_certificates = _load_required_file(managed_path)
    enterprise_sources = _additional_sources(required_additional, optional_dirs)
    combined: list[Certificate] = []
    combined_fingerprints: set[str] = set()
    for certificate in managed_certificates + [
        certificate
        for _source, certificates in enterprise_sources
        for certificate in certificates
    ]:
        if certificate.fingerprint not in combined_fingerprints:
            combined.append(certificate)
            combined_fingerprints.add(certificate.fingerprint)
    _atomic_write(runtime_path, b"".join(certificate.pem for certificate in combined))

    nss_path.mkdir(parents=True, exist_ok=True)
    nss_path.chmod(0o700)
    database = f"sql:{nss_path}"
    if not (nss_path / "cert9.db").exists():
        _run_certutil(["-N", "-d", database, "--empty-password"])

    previous_nicknames = _read_previous_nicknames(status_path)
    active_nicknames: set[str] = set()
    roots = 0
    intermediates = 0
    with tempfile.TemporaryDirectory(prefix="portal-validator-ca-", dir=runtime_path.parent) as directory:
        temporary_directory = Path(directory)
        for source, certificates in enterprise_sources:
            for index, certificate in enumerate(certificates, start=1):
                certificate_path = temporary_directory / f"certificate-{len(active_nicknames) + 1}.pem"
                certificate_path.write_bytes(certificate.pem)
                certificate_path.chmod(0o600)
                is_root = _is_self_signed(certificate_path)
                trust = "C,," if is_root else ",,"
                roots += int(is_root)
                intermediates += int(not is_root)
                nickname = _stable_nickname(source, index)
                active_nicknames.add(nickname)
                _run_certutil(["-D", "-d", database, "-n", nickname], check=False)
                _run_certutil([
                    "-A", "-d", database, "-n", nickname, "-t", trust,
                    "-i", str(certificate_path),
                ])
                _run_certutil(["-L", "-d", database, "-n", nickname])

    if enterprise_sources and roots == 0:
        raise RuntimeError("Configured enterprise CA inputs contain no self-signed root CA")
    for stale_nickname in sorted(previous_nicknames - active_nicknames):
        _run_certutil(["-D", "-d", database, "-n", stale_nickname], check=False)

    status = TrustStatus(
        enabled=True,
        certificates=len(combined),
        roots=roots,
        intermediates=intermediates,
        runtime_bundle=str(runtime_path),
    )
    state = {
        **asdict(status),
        "nss_nicknames": sorted(active_nicknames),
    }
    _atomic_write(status_path, (json.dumps(state, sort_keys=True) + "\n").encode())
    log_event(
        20,
        "TRUST_INITIALIZATION_COMPLETED",
        managed_certificates=len(managed_certificates),
        enterprise_roots=roots,
        enterprise_intermediates=intermediates,
        runtime_bundle=str(runtime_path),
    )
    return status


def inspect_trust_status() -> TrustStatus:
    home = Path(os.environ.get("HOME") or "/tmp/portal-validator-home")
    status_path = Path(os.getenv(
        "PORTAL_VALIDATOR_TRUST_STATUS",
        str(home / ".portal-validator/trust-status.json"),
    ))
    try:
        payload = json.loads(status_path.read_text(encoding="utf-8"))
        return TrustStatus(
            enabled=bool(payload.get("enabled")),
            certificates=int(payload.get("certificates", 0)),
            roots=int(payload.get("roots", 0)),
            intermediates=int(payload.get("intermediates", 0)),
            runtime_bundle=payload.get("runtime_bundle"),
        )
    except (OSError, ValueError, TypeError):
        return TrustStatus(enabled=False)


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"initialize", "status"}:
        print("usage: python -m app.trust {initialize|status}", file=sys.stderr)
        return 2
    try:
        status = bootstrap_trust() if sys.argv[1] == "initialize" else inspect_trust_status()
    except RuntimeError as exc:
        log_event(40, "TRUST_INITIALIZATION_FAILED", error=str(exc))
        return 1
    if sys.argv[1] == "status":
        print(json.dumps(asdict(status), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
