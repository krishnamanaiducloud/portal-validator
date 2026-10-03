from __future__ import annotations

import hashlib
import json
import logging
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
DEFAULT_ENTERPRISE_CA_DIRECTORY = "/etc/portal-validator/zscaler"
SUPPORTED_CERTIFICATE_SUFFIXES = frozenset({".crt", ".pem", ".cer"})
MANAGED_NICKNAME_PREFIX = "portal-validator-enterprise-"


@dataclass(frozen=True)
class TrustStatus:
    enabled: bool
    certificates: int = 0
    roots: int = 0
    intermediates: int = 0
    runtime_bundle: str | None = None
    managed_certificates: int = 0
    enterprise_certificates: int = 0
    enterprise_roots: int = 0
    enterprise_intermediates: int = 0
    duplicates: int = 0
    runtime_certificates: int = 0
    nss_nicknames: tuple[str, ...] = ()


@dataclass(frozen=True)
class Certificate:
    pem: bytes
    fingerprint: str


@dataclass(frozen=True)
class EnterpriseCertificate:
    certificate: Certificate
    source: Path
    index: int
    subject: str
    is_root: bool


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


def _read_required_bytes(path: Path) -> bytes:
    try:
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError(f"Required CA file is missing or empty: {path}")
        content = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Required CA file is unreadable: {path}") from exc
    if len(content) > MAX_BUNDLE_BYTES:
        raise RuntimeError(f"CA input exceeds the 10 MiB limit: {path}")
    if b"PRIVATE KEY" in content:
        raise RuntimeError(f"CA input must not contain private keys: {path}")
    return content


def _load_managed_bundle(path: Path) -> list[Certificate]:
    return extract_certificates(_read_required_bytes(path))


def _load_certificate_file(path: Path) -> list[Certificate]:
    content = _read_required_bytes(path)
    if b"-----BEGIN CERTIFICATE-----" in content:
        return extract_certificates(content)
    try:
        pem = ssl.DER_cert_to_PEM_cert(content).encode("ascii")
        return extract_certificates(pem)
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError(f"CA input is not a valid PEM or DER certificate: {path}") from exc


def _certificate_paths(directory: Path, *, optional: bool) -> list[Path]:
    if not directory.exists():
        if optional:
            log_event(logging.WARNING, "OPTIONAL_CA_DIRECTORY_SKIPPED", path=str(directory))
            return []
        raise RuntimeError(f"Configured corporate CA directory does not exist: {directory}")
    if not directory.is_dir():
        raise RuntimeError(f"Configured corporate CA path is not a directory: {directory}")

    log_event(logging.INFO, "CORPORATE_CA_DIRECTORY_FOUND", path=str(directory))
    discovered: list[Path] = []
    errors: list[OSError] = []
    for root, directory_names, file_names in os.walk(
        directory,
        topdown=True,
        onerror=errors.append,
        followlinks=False,
    ):
        # Kubernetes projected volumes expose both public symlinks and ..data backing
        # directories. Process the public entries and do not traverse the backing tree.
        directory_names[:] = sorted(
            name for name in directory_names if not name.startswith("..")
        )
        root_path = Path(root)
        for name in sorted(file_names):
            path = root_path / name
            if path.suffix.lower() in SUPPORTED_CERTIFICATE_SUFFIXES:
                discovered.append(path)
    if errors:
        raise RuntimeError(f"Configured corporate CA directory is unreadable: {directory}")
    return discovered


def _discover_sources(
    files: list[Path],
    directories: list[Path],
    optional_directories: list[Path] | None = None,
) -> list[tuple[Path, list[Certificate]]]:
    paths = list(files)
    for directory in directories:
        paths.extend(_certificate_paths(directory, optional=False))
    for directory in optional_directories or []:
        paths.extend(_certificate_paths(directory, optional=True))

    sources = [(path, _load_certificate_file(path)) for path in paths]
    log_event(
        logging.INFO,
        "CORPORATE_CA_DISCOVERY_COMPLETED",
        discovered=len(paths),
        parsed_certificates=sum(len(certificates) for _path, certificates in sources),
    )
    return sources


def _atomic_write(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(content)
        temporary.chmod(mode)
        temporary.replace(path)
    except OSError as exc:
        raise RuntimeError(f"Unable to create runtime trust file: {path}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _run_command(command: list[str], *, error: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise RuntimeError(error) from exc


def _run_certutil(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = _run_command(
        ["certutil", *arguments],
        error="certutil failed while initializing Chromium trust",
    )
    if check and result.returncode != 0:
        raise RuntimeError("certutil failed while initializing Chromium trust")
    return result


def _safe_subject(details: dict[str, object]) -> str:
    values: list[str] = []
    for relative_name in details.get("subject", ()):  # type: ignore[union-attr]
        for key, value in relative_name:
            values.append(f"{key}={value}")
    return ",".join(values) or "subject-unavailable"


def _classify_certificate(certificate_path: Path) -> tuple[bool, bool, str]:
    try:
        details = ssl._ssl._test_decode_cert(str(certificate_path))  # type: ignore[attr-defined]
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError("Unable to parse a configured corporate X.509 certificate") from exc

    purpose = _run_command(
        ["openssl", "x509", "-in", str(certificate_path), "-noout", "-purpose"],
        error="OpenSSL failed while validating a corporate certificate",
    )
    if purpose.returncode != 0:
        raise RuntimeError("Unable to parse a configured corporate X.509 certificate")
    is_ca = any(
        line.strip() == "SSL server CA : Yes" for line in purpose.stdout.splitlines()
    )
    subject = _safe_subject(details)
    self_issued = details.get("subject") == details.get("issuer")
    is_root = False
    if is_ca and self_issued:
        verification = _run_command(
            [
                "openssl", "verify", "-no_check_time", "-CAfile",
                str(certificate_path), str(certificate_path),
            ],
            error="OpenSSL failed while verifying a corporate root certificate",
        )
        if verification.returncode != 0:
            raise RuntimeError("A self-issued corporate CA certificate failed signature verification")
        is_root = True
    return is_ca, is_root, subject


def _prepare_enterprise_certificates(
    sources: list[tuple[Path, list[Certificate]]],
    temporary_directory: Path,
    *,
    prefix: str,
) -> tuple[list[EnterpriseCertificate], int]:
    prepared: list[EnterpriseCertificate] = []
    fingerprints: set[str] = set()
    duplicates = 0
    item_number = 0
    for source, certificates in sources:
        for index, certificate in enumerate(certificates, start=1):
            item_number += 1
            certificate_path = temporary_directory / f"{prefix}-{item_number}.pem"
            certificate_path.write_bytes(certificate.pem)
            certificate_path.chmod(0o600)
            is_ca, is_root, subject = _classify_certificate(certificate_path)
            log_event(
                logging.INFO,
                "ENTERPRISE_CERTIFICATE_PARSED",
                path=str(source),
                fingerprint_sha256=certificate.fingerprint,
                subject=subject,
                is_ca=is_ca,
            )
            if not is_ca:
                log_event(
                    logging.WARNING,
                    "ENTERPRISE_CERTIFICATE_SKIPPED",
                    path=str(source),
                    fingerprint_sha256=certificate.fingerprint,
                    reason="not_valid_for_ssl_ca_usage",
                )
                continue
            if certificate.fingerprint in fingerprints:
                duplicates += 1
                log_event(
                    logging.INFO,
                    "ENTERPRISE_CERTIFICATE_DUPLICATE",
                    fingerprint_sha256=certificate.fingerprint,
                )
                continue
            fingerprints.add(certificate.fingerprint)
            prepared.append(EnterpriseCertificate(
                certificate=certificate,
                source=source,
                index=index,
                subject=subject,
                is_root=is_root,
            ))
            log_event(
                logging.INFO,
                "ENTERPRISE_ROOT_IDENTIFIED" if is_root else "ENTERPRISE_INTERMEDIATE_IDENTIFIED",
                fingerprint_sha256=certificate.fingerprint,
                subject=subject,
            )
    return prepared, duplicates


def _stable_nickname(source: Path, index: int) -> str:
    # Do not resolve ConfigMap symlinks: the timestamped ..data target changes on rotation.
    logical_path = os.path.abspath(os.fspath(source))
    identity = hashlib.sha256(f"{logical_path}:{index}".encode()).hexdigest()[:20]
    return f"{MANAGED_NICKNAME_PREFIX}{identity}"


def _read_previous_nicknames(state_path: Path) -> set[str]:
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return set()
    return {
        value for value in payload.get("nss_nicknames", [])
        if isinstance(value, str) and value.startswith(MANAGED_NICKNAME_PREFIX)
    }


def _nss_trust(database: str, nickname: str) -> str | None:
    result = _run_certutil(["-L", "-d", database], check=False)
    if result.returncode != 0:
        raise RuntimeError("Unable to list Chromium NSS trust database")
    pattern = re.compile(rf"^{re.escape(nickname)}\s+(\S+)\s*$")
    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())
        if match:
            return match.group(1)
    return None


def _nss_certificate(database: str, nickname: str) -> Certificate | None:
    result = _run_certutil(["-L", "-d", database, "-n", nickname, "-a"], check=False)
    if result.returncode != 0:
        return None
    certificates = extract_certificates(result.stdout.encode("ascii"))
    if len(certificates) != 1:
        raise RuntimeError("Chromium NSS entry did not contain exactly one certificate")
    return certificates[0]


def _verify_nss_entry(
    database: str,
    nickname: str,
    certificate: Certificate,
) -> None:
    imported = _nss_certificate(database, nickname)
    if imported is None or imported.fingerprint != certificate.fingerprint:
        raise RuntimeError("Chromium NSS certificate verification failed")
    if _nss_trust(database, nickname) != "C,,":
        raise RuntimeError("Chromium NSS root trust verification failed")


def _import_browser_root(
    database: str,
    nickname: str,
    certificate: Certificate,
    certificate_path: Path,
) -> str:
    existing = _nss_certificate(database, nickname)
    existing_trust = _nss_trust(database, nickname) if existing is not None else None
    if (
        existing is not None
        and existing.fingerprint == certificate.fingerprint
        and existing_trust == "C,,"
    ):
        return "already_present"

    if existing is not None and existing.fingerprint == certificate.fingerprint:
        _run_certutil(["-M", "-d", database, "-n", nickname, "-t", "C,,"])
        _verify_nss_entry(database, nickname, certificate)
        return "imported"

    if existing is not None:
        temporary_nickname = f"{nickname}-rotation-{certificate.fingerprint[:12]}"
        _run_certutil(["-D", "-d", database, "-n", temporary_nickname], check=False)
        _run_certutil([
            "-A", "-d", database, "-n", temporary_nickname, "-t", "C,,",
            "-i", str(certificate_path),
        ])
        _verify_nss_entry(database, temporary_nickname, certificate)
        _run_certutil(["-D", "-d", database, "-n", nickname])
        _run_certutil([
            "-A", "-d", database, "-n", nickname, "-t", "C,,",
            "-i", str(certificate_path),
        ])
        _verify_nss_entry(database, nickname, certificate)
        _run_certutil(["-D", "-d", database, "-n", temporary_nickname])
        return "imported"

    _run_certutil([
        "-A", "-d", database, "-n", nickname, "-t", "C,,",
        "-i", str(certificate_path),
    ])
    _verify_nss_entry(database, nickname, certificate)
    return "imported"


def _required_directory_configuration(
    explicit: list[Path] | None,
    variable: str,
) -> list[Path]:
    if explicit is not None:
        directories = explicit
    elif variable in os.environ:
        directories = _configured_paths(variable)
    else:
        directories = [Path(DEFAULT_ENTERPRISE_CA_DIRECTORY)]
    if not directories:
        raise RuntimeError(f"{variable} must identify at least one corporate CA directory")
    return directories


def bootstrap_trust(
    *,
    managed_bundle_path: str | None = None,
    additional_files: list[Path] | None = None,
    additional_directories: list[Path] | None = None,
    optional_directories: list[Path] | None = None,
    browser_files: list[Path] | None = None,
    browser_directories: list[Path] | None = None,
    runtime_bundle_path: str | None = None,
    nss_database_path: str | None = None,
    state_path: str | None = None,
) -> TrustStatus:
    log_event(logging.INFO, "TRUST_INITIALIZATION_STARTED")
    if not shutil.which("certutil"):
        raise RuntimeError("certutil is required to initialize Chromium enterprise trust")
    if not shutil.which("openssl"):
        raise RuntimeError("openssl is required to validate corporate X.509 certificates")

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
    additional_dirs = _required_directory_configuration(
        additional_directories,
        "PORTAL_VALIDATOR_ADDITIONAL_CA_DIRS",
    )
    optional_dirs = optional_directories if optional_directories is not None else _configured_paths(
        "PORTAL_VALIDATOR_OPTIONAL_CA_DIRS"
    )
    browser_directory_explicit = (
        browser_directories is not None
        or "PORTAL_VALIDATOR_BROWSER_CA_DIRS" in os.environ
    )
    browser_configuration_explicit = (
        browser_files is not None
        or "PORTAL_VALIDATOR_BROWSER_CA_FILES" in os.environ
        or browser_directory_explicit
    )
    configured_browser_files = browser_files if browser_files is not None else _configured_paths(
        "PORTAL_VALIDATOR_BROWSER_CA_FILES"
    )
    configured_browser_dirs = (
        _required_directory_configuration(browser_directories, "PORTAL_VALIDATOR_BROWSER_CA_DIRS")
        if browser_directory_explicit
        else additional_dirs
    )

    managed_certificates = _load_managed_bundle(managed_path)
    log_event(
        logging.INFO,
        "MANAGED_CA_BUNDLE_FOUND",
        path=str(managed_path),
        certificates=len(managed_certificates),
    )
    enterprise_sources = _discover_sources(
        required_additional,
        additional_dirs,
        optional_dirs,
    )

    browser_uses_enterprise_sources = (
        not browser_configuration_explicit
        or (
            configured_browser_files == required_additional
            and configured_browser_dirs == additional_dirs
            and not optional_dirs
        )
    )
    browser_sources = (
        enterprise_sources
        if browser_uses_enterprise_sources
        else _discover_sources(configured_browser_files, configured_browser_dirs)
    )

    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_path.parent.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix="portal-validator-ca-", dir=runtime_path.parent) as directory:
        temporary_directory = Path(directory)
        enterprise, duplicates = _prepare_enterprise_certificates(
            enterprise_sources,
            temporary_directory,
            prefix="enterprise",
        )
        enterprise_roots = sum(certificate.is_root for certificate in enterprise)
        enterprise_intermediates = len(enterprise) - enterprise_roots
        if not enterprise:
            raise RuntimeError("Configured corporate CA directory contains no usable CA certificates")
        if enterprise_roots == 0:
            raise RuntimeError("Configured corporate CA directory contains no usable root CA certificates")

        if browser_uses_enterprise_sources:
            browser_certificates = enterprise
        else:
            browser_certificates, _browser_duplicates = _prepare_enterprise_certificates(
                browser_sources,
                temporary_directory,
                prefix="browser",
            )
        browser_roots = [certificate for certificate in browser_certificates if certificate.is_root]
        if not browser_roots:
            raise RuntimeError("Configured browser CA directory contains no usable root CA certificates")

        combined: list[Certificate] = []
        combined_fingerprints: set[str] = set()
        for certificate in managed_certificates:
            if certificate.fingerprint not in combined_fingerprints:
                combined.append(certificate)
                combined_fingerprints.add(certificate.fingerprint)
        for enterprise_certificate in enterprise:
            certificate = enterprise_certificate.certificate
            if certificate.fingerprint in combined_fingerprints:
                duplicates += 1
                log_event(
                    logging.INFO,
                    "ENTERPRISE_CERTIFICATE_DUPLICATE",
                    fingerprint_sha256=certificate.fingerprint,
                )
                continue
            combined.append(certificate)
            combined_fingerprints.add(certificate.fingerprint)
        _atomic_write(runtime_path, b"".join(certificate.pem for certificate in combined))
        log_event(
            logging.INFO,
            "RUNTIME_CA_BUNDLE_CREATED",
            path=str(runtime_path),
            certificates=len(combined),
        )

        nss_path.mkdir(parents=True, exist_ok=True)
        nss_path.chmod(0o700)
        database = f"sql:{nss_path}"
        database_created = not (nss_path / "cert9.db").exists()
        if database_created:
            _run_certutil(["-N", "-d", database, "--empty-password"])
        log_event(logging.INFO, "NSS_DB_INITIALIZED", path=str(nss_path), created=database_created)

        previous_nicknames = _read_previous_nicknames(status_path)
        active_nicknames: set[str] = set()
        for item_number, root in enumerate(browser_roots, start=1):
            certificate_path = temporary_directory / f"nss-root-{item_number}.pem"
            certificate_path.write_bytes(root.certificate.pem)
            certificate_path.chmod(0o600)
            nickname = _stable_nickname(root.source, root.index)
            active_nicknames.add(nickname)
            result = _import_browser_root(
                database,
                nickname,
                root.certificate,
                certificate_path,
            )
            log_event(
                logging.INFO,
                "NSS_ROOT_ALREADY_PRESENT" if result == "already_present" else "NSS_ROOT_IMPORTED",
                nickname=nickname,
                fingerprint_sha256=root.certificate.fingerprint,
                subject=root.subject,
            )

        for stale_nickname in sorted(previous_nicknames - active_nicknames):
            _run_certutil(["-D", "-d", database, "-n", stale_nickname], check=False)

    nicknames = tuple(sorted(active_nicknames))
    status = TrustStatus(
        enabled=True,
        certificates=len(combined),
        roots=enterprise_roots,
        intermediates=enterprise_intermediates,
        runtime_bundle=str(runtime_path),
        managed_certificates=len(managed_certificates),
        enterprise_certificates=len(enterprise),
        enterprise_roots=enterprise_roots,
        enterprise_intermediates=enterprise_intermediates,
        duplicates=duplicates,
        runtime_certificates=len(combined),
        nss_nicknames=nicknames,
    )
    _atomic_write(status_path, (json.dumps(asdict(status), sort_keys=True) + "\n").encode())
    log_event(
        logging.INFO,
        "TRUST_INITIALIZATION_COMPLETED",
        managed_certificates=status.managed_certificates,
        enterprise_certificates=status.enterprise_certificates,
        enterprise_roots=status.enterprise_roots,
        enterprise_intermediates=status.enterprise_intermediates,
        duplicates=status.duplicates,
        runtime_certificates=status.runtime_certificates,
        nss_roots=len(status.nss_nicknames),
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
        runtime_certificates = int(
            payload.get("runtime_certificates", payload.get("certificates", 0))
        )
        enterprise_roots = int(payload.get("enterprise_roots", payload.get("roots", 0)))
        enterprise_intermediates = int(
            payload.get("enterprise_intermediates", payload.get("intermediates", 0))
        )
        return TrustStatus(
            enabled=bool(payload.get("enabled")),
            certificates=int(payload.get("certificates", runtime_certificates)),
            roots=int(payload.get("roots", enterprise_roots)),
            intermediates=int(payload.get("intermediates", enterprise_intermediates)),
            runtime_bundle=payload.get("runtime_bundle"),
            managed_certificates=int(payload.get("managed_certificates", 0)),
            enterprise_certificates=int(payload.get("enterprise_certificates", 0)),
            enterprise_roots=enterprise_roots,
            enterprise_intermediates=enterprise_intermediates,
            duplicates=int(payload.get("duplicates", 0)),
            runtime_certificates=runtime_certificates,
            nss_nicknames=tuple(
                value for value in payload.get("nss_nicknames", [])
                if isinstance(value, str)
            ),
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
        log_event(logging.ERROR, "TRUST_INITIALIZATION_FAILED", error=str(exc))
        return 1
    if sys.argv[1] == "status":
        print(json.dumps(asdict(status), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
