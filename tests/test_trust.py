import hashlib
import json
import logging
import os
import subprocess
from pathlib import Path

import pytest

from app import trust
from app.logging_config import RedactingFilter
from app.trust import Certificate, bootstrap_trust, extract_certificates, inspect_trust_status


TRUST_ENVIRONMENT = (
    "PORTAL_VALIDATOR_ADDITIONAL_CA_FILES",
    "PORTAL_VALIDATOR_ADDITIONAL_CA_DIRS",
    "PORTAL_VALIDATOR_OPTIONAL_CA_DIRS",
    "PORTAL_VALIDATOR_BROWSER_CA_FILES",
    "PORTAL_VALIDATOR_BROWSER_CA_DIRS",
)


@pytest.fixture(autouse=True)
def clear_trust_environment(monkeypatch):
    for variable in TRUST_ENVIRONMENT:
        monkeypatch.delenv(variable, raising=False)


def _mock_certificate(name: str) -> Certificate:
    marker = name.encode()
    return Certificate(
        pem=b"-----BEGIN CERTIFICATE-----\n" + marker + b"\n-----END CERTIFICATE-----\n",
        fingerprint=hashlib.sha256(marker).hexdigest(),
    )


def _install_mock_parser(monkeypatch, mapping: dict[bytes, list[Certificate]]):
    expanded = dict(mapping)
    for certificates in mapping.values():
        for certificate in certificates:
            expanded[certificate.pem] = [certificate]

    def fake_extract(content: bytes):
        try:
            return expanded[content]
        except KeyError as exc:
            raise RuntimeError("CA input contains no PEM certificates") from exc

    monkeypatch.setattr(trust, "extract_certificates", fake_extract)
    monkeypatch.setattr(
        trust,
        "_load_certificate_file",
        lambda path: fake_extract(path.read_bytes()),
    )


class FakeNSS:
    def __init__(self, database_path: Path):
        self.database_path = database_path
        self.entries: dict[str, tuple[Certificate, str]] = {}
        self.calls: list[tuple[tuple[str, ...], bool]] = []

    def __call__(self, arguments: list[str], check: bool = True):
        self.calls.append((tuple(arguments), check))
        if "-N" in arguments:
            self.database_path.mkdir(parents=True, exist_ok=True)
            (self.database_path / "cert9.db").touch()
            return subprocess.CompletedProcess(arguments, 0, "", "")

        nickname = arguments[arguments.index("-n") + 1] if "-n" in arguments else None
        if "-A" in arguments:
            certificate_path = Path(arguments[arguments.index("-i") + 1])
            certificate = trust.extract_certificates(certificate_path.read_bytes())[0]
            trust_value = arguments[arguments.index("-t") + 1]
            self.entries[str(nickname)] = (certificate, trust_value)
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if "-M" in arguments:
            certificate, _old_trust = self.entries[str(nickname)]
            self.entries[str(nickname)] = (
                certificate,
                arguments[arguments.index("-t") + 1],
            )
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if "-D" in arguments:
            existed = self.entries.pop(str(nickname), None) is not None
            if check and not existed:
                raise RuntimeError("missing NSS entry")
            return subprocess.CompletedProcess(arguments, 0 if existed else 255, "", "")
        if "-L" in arguments and nickname is not None:
            entry = self.entries.get(str(nickname))
            if entry is None:
                return subprocess.CompletedProcess(arguments, 255, "", "not found")
            return subprocess.CompletedProcess(arguments, 0, entry[0].pem.decode(), "")
        if "-L" in arguments:
            output = "\n".join(
                f"{entry_nickname} {entry_trust}"
                for entry_nickname, (_certificate, entry_trust) in sorted(self.entries.items())
            )
            return subprocess.CompletedProcess(arguments, 0, output, "")
        raise AssertionError(f"Unexpected certutil arguments: {arguments}")

    def mutation_count(self) -> int:
        return sum(
            any(option in arguments for option in ("-A", "-D", "-M"))
            for arguments, _check in self.calls
        )


def _install_fake_nss(monkeypatch, nss_path: Path) -> FakeNSS:
    fake = FakeNSS(nss_path)
    monkeypatch.setattr(trust.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(trust, "_run_certutil", fake)

    def classify(path: Path):
        content = path.read_bytes()
        if b"leaf" in content:
            return False, False, "commonName=leaf"
        if b"intermediate" in content:
            return True, False, "commonName=intermediate"
        return True, True, "commonName=enterprise-root"

    monkeypatch.setattr(trust, "_classify_certificate", classify)
    return fake


def _bootstrap_arguments(tmp_path: Path, managed: Path, corporate: Path) -> dict[str, object]:
    return {
        "managed_bundle_path": str(managed),
        "additional_directories": [corporate],
        "runtime_bundle_path": str(tmp_path / "runtime.pem"),
        "nss_database_path": str(tmp_path / "nss"),
        "state_path": str(tmp_path / "status.json"),
    }


def test_invalid_and_private_key_ca_inputs_are_rejected():
    with pytest.raises(RuntimeError, match="contains no PEM certificates"):
        extract_certificates(b"not a certificate")
    with pytest.raises(RuntimeError, match="must not contain private keys"):
        extract_certificates(b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----")


def test_missing_managed_bundle_is_rejected(tmp_path, monkeypatch):
    corporate = tmp_path / "corporate"
    corporate.mkdir()
    monkeypatch.setattr(trust.shutil, "which", lambda command: f"/usr/bin/{command}")
    with pytest.raises(RuntimeError, match="missing or empty"):
        bootstrap_trust(
            managed_bundle_path=str(tmp_path / "missing.pem"),
            additional_directories=[corporate],
        )


def test_default_directory_combines_deduplicates_and_imports_roots(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    corporate = tmp_path / "zscaler"
    nested = corporate / "nested"
    nested.mkdir(parents=True)
    managed.write_bytes(b"managed")
    (corporate / "root-one.crt").write_bytes(b"root-one")
    (nested / "root-two.cer").write_bytes(b"root-two")

    root_one = _mock_certificate("root-one")
    root_two = _mock_certificate("root-two")
    _install_mock_parser(monkeypatch, {
        b"managed": [root_one],
        b"root-one": [root_one],
        b"root-two": [root_two],
    })
    runtime = tmp_path / "home" / "ca-bundle.crt"
    nss_path = tmp_path / "home" / "nssdb"
    state = tmp_path / "home" / "trust-status.json"
    fake_nss = _install_fake_nss(monkeypatch, nss_path)
    monkeypatch.setattr(trust, "DEFAULT_ENTERPRISE_CA_DIRECTORY", str(corporate))
    monkeypatch.setenv("PORTAL_VALIDATOR_MANAGED_CA_BUNDLE", str(managed))
    monkeypatch.setenv("RUNTIME_CA_BUNDLE", str(runtime))
    monkeypatch.setenv("CHROMIUM_NSS_DB", str(nss_path))
    monkeypatch.setenv("PORTAL_VALIDATOR_TRUST_STATUS", str(state))

    status = bootstrap_trust()

    assert status.enabled is True
    assert status.managed_certificates == 1
    assert status.enterprise_certificates == 2
    assert status.enterprise_roots == status.roots == 2
    assert status.enterprise_intermediates == 0
    assert status.duplicates == 1
    assert status.runtime_certificates == status.certificates == 2
    assert runtime.read_bytes() == root_one.pem + root_two.pem
    assert len(fake_nss.entries) == 2
    assert {entry[0].fingerprint for entry in fake_nss.entries.values()} == {
        root_one.fingerprint,
        root_two.fingerprint,
    }
    assert all(entry[1] == "C,," for entry in fake_nss.entries.values())
    payload = json.loads(state.read_text())
    assert payload["enterprise_certificates"] == 2
    assert len(payload["nss_nicknames"]) == 2


def test_multiple_colon_separated_directories_are_discovered(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    managed.write_bytes(b"managed")
    (first / "one.crt").write_bytes(b"one")
    (second / "two.pem").write_bytes(b"two")
    certificates = {
        b"managed": [_mock_certificate("managed")],
        b"one": [_mock_certificate("one")],
        b"two": [_mock_certificate("two")],
    }
    _install_mock_parser(monkeypatch, certificates)
    _install_fake_nss(monkeypatch, tmp_path / "nss")
    monkeypatch.setenv(
        "PORTAL_VALIDATOR_ADDITIONAL_CA_DIRS",
        os.pathsep.join((str(first), str(second))),
    )

    status = bootstrap_trust(
        managed_bundle_path=str(managed),
        runtime_bundle_path=str(tmp_path / "runtime.pem"),
        nss_database_path=str(tmp_path / "nss"),
        state_path=str(tmp_path / "status.json"),
    )
    assert status.enterprise_certificates == 2
    assert status.enterprise_roots == 2


def test_kubernetes_configmap_symlink_layout_processes_each_public_file_once(tmp_path):
    mount = tmp_path / "zscaler"
    version = mount / "..2026_10_03_18_13_39"
    version.mkdir(parents=True)
    (version / "root-one.crt").write_bytes(b"one")
    (version / "root-two.crt").write_bytes(b"two")
    try:
        (mount / "..data").symlink_to(version.name, target_is_directory=True)
        (mount / "root-one.crt").symlink_to("..data/root-one.crt")
        (mount / "root-two.crt").symlink_to("..data/root-two.crt")
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    paths = trust._certificate_paths(mount, optional=False)
    assert paths == [mount / "root-one.crt", mount / "root-two.crt"]


def test_managed_general_bundle_is_not_imported_into_nss(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    corporate = tmp_path / "corporate"
    corporate.mkdir()
    managed.write_bytes(b"managed-149")
    (corporate / "enterprise.crt").write_bytes(b"enterprise")
    managed_certificates = [_mock_certificate(f"public-{index}") for index in range(149)]
    enterprise = _mock_certificate("enterprise")
    _install_mock_parser(monkeypatch, {
        b"managed-149": managed_certificates,
        b"enterprise": [enterprise],
    })
    nss_path = tmp_path / "nss"
    fake_nss = _install_fake_nss(monkeypatch, nss_path)

    status = bootstrap_trust(**_bootstrap_arguments(tmp_path, managed, corporate))

    assert status.managed_certificates == 149
    assert status.runtime_certificates == 150
    assert len(fake_nss.entries) == 1
    assert next(iter(fake_nss.entries.values()))[0] == enterprise


def test_intermediate_is_added_to_pem_but_never_given_nss_root_trust(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    corporate = tmp_path / "corporate"
    corporate.mkdir()
    managed.write_bytes(b"managed")
    (corporate / "root.crt").write_bytes(b"root")
    (corporate / "intermediate.crt").write_bytes(b"intermediate")
    managed_certificate = _mock_certificate("managed")
    root = _mock_certificate("root")
    intermediate = _mock_certificate("intermediate")
    _install_mock_parser(monkeypatch, {
        b"managed": [managed_certificate],
        b"root": [root],
        b"intermediate": [intermediate],
    })
    fake_nss = _install_fake_nss(monkeypatch, tmp_path / "nss")

    status = bootstrap_trust(**_bootstrap_arguments(tmp_path, managed, corporate))

    assert status.enterprise_roots == 1
    assert status.enterprise_intermediates == 1
    assert status.runtime_certificates == 3
    assert len(fake_nss.entries) == 1
    assert next(iter(fake_nss.entries.values())) == (root, "C,,")


def test_nss_initialization_is_idempotent_and_preserves_correct_entry(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    corporate = tmp_path / "corporate"
    corporate.mkdir()
    managed.write_bytes(b"managed")
    (corporate / "root.crt").write_bytes(b"root")
    managed_certificate = _mock_certificate("managed")
    root = _mock_certificate("root")
    _install_mock_parser(monkeypatch, {b"managed": [managed_certificate], b"root": [root]})
    fake_nss = _install_fake_nss(monkeypatch, tmp_path / "nss")
    arguments = _bootstrap_arguments(tmp_path, managed, corporate)

    first = bootstrap_trust(**arguments)
    mutations = fake_nss.mutation_count()
    second = bootstrap_trust(**arguments)

    assert first.nss_nicknames == second.nss_nicknames
    assert fake_nss.mutation_count() == mutations
    assert len([call for call, _check in fake_nss.calls if "-N" in call]) == 1


def test_rotated_browser_root_is_replaced_safely(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    corporate = tmp_path / "corporate"
    corporate.mkdir()
    root_path = corporate / "root.crt"
    managed.write_bytes(b"managed")
    root_path.write_bytes(b"old-root")
    managed_certificate = _mock_certificate("managed")
    old_root = _mock_certificate("old-root")
    new_root = _mock_certificate("new-root")
    _install_mock_parser(monkeypatch, {b"managed": [managed_certificate], b"old-root": [old_root]})
    fake_nss = _install_fake_nss(monkeypatch, tmp_path / "nss")
    arguments = _bootstrap_arguments(tmp_path, managed, corporate)
    first = bootstrap_trust(**arguments)
    root_path.write_bytes(b"new-root")
    _install_mock_parser(monkeypatch, {
        b"managed": [managed_certificate],
        b"old-root": [old_root],
        b"new-root": [new_root],
    })

    second = bootstrap_trust(**arguments)

    assert first.nss_nicknames == second.nss_nicknames
    assert len(fake_nss.entries) == 1
    assert next(iter(fake_nss.entries.values())) == (new_root, "C,,")
    assert not any("-rotation-" in nickname for nickname in fake_nss.entries)


def test_malformed_or_empty_required_directory_fails_startup(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    malformed = tmp_path / "malformed"
    empty = tmp_path / "empty"
    malformed.mkdir()
    empty.mkdir()
    managed.write_bytes(b"managed")
    (malformed / "bad.crt").write_bytes(b"not-a-certificate")
    managed_certificate = _mock_certificate("managed")
    _install_mock_parser(monkeypatch, {b"managed": [managed_certificate]})
    _install_fake_nss(monkeypatch, tmp_path / "nss")

    with pytest.raises(RuntimeError, match="contains no PEM certificates"):
        bootstrap_trust(**_bootstrap_arguments(tmp_path, managed, malformed))
    with pytest.raises(RuntimeError, match="no usable CA certificates"):
        bootstrap_trust(**_bootstrap_arguments(tmp_path, managed, empty))


def test_non_ca_is_skipped_and_absent_optional_directory_is_safe(tmp_path, monkeypatch):
    managed = tmp_path / "managed.pem"
    corporate = tmp_path / "corporate"
    corporate.mkdir()
    managed.write_bytes(b"managed")
    (corporate / "root.crt").write_bytes(b"root")
    (corporate / "leaf.crt").write_bytes(b"leaf")
    managed_certificate = _mock_certificate("managed")
    root = _mock_certificate("root")
    leaf = _mock_certificate("leaf")
    _install_mock_parser(monkeypatch, {
        b"managed": [managed_certificate],
        b"root": [root],
        b"leaf": [leaf],
    })
    _install_fake_nss(monkeypatch, tmp_path / "nss")

    status = bootstrap_trust(
        **_bootstrap_arguments(tmp_path, managed, corporate),
        optional_directories=[tmp_path / "not-mounted"],
    )
    assert status.enterprise_certificates == 1
    assert status.runtime_certificates == 2


def test_status_inspection_reports_non_sensitive_metadata(tmp_path, monkeypatch):
    status_path = tmp_path / "trust-status.json"
    status_path.write_text(json.dumps({
        "enabled": True,
        "certificates": 150,
        "roots": 2,
        "intermediates": 1,
        "runtime_bundle": "/tmp/ca.pem",
        "managed_certificates": 149,
        "enterprise_certificates": 3,
        "enterprise_roots": 2,
        "enterprise_intermediates": 1,
        "duplicates": 2,
        "runtime_certificates": 150,
        "nss_nicknames": ["portal-validator-enterprise-one"],
    }))
    monkeypatch.setenv("PORTAL_VALIDATOR_TRUST_STATUS", str(status_path))
    status = inspect_trust_status()
    assert status.runtime_certificates == 150
    assert status.managed_certificates == 149
    assert status.enterprise_certificates == 3
    assert status.enterprise_roots == 2
    assert status.duplicates == 2
    assert status.nss_nicknames == ("portal-validator-enterprise-one",)


def test_entrypoint_and_deployment_use_existing_combined_ca_mount():
    root = Path(__file__).resolve().parents[1]
    script = (root / "container-entrypoint.sh").read_text()
    deployment = (root / "openshift" / "deployment.yaml").read_text()
    assert script.count("python -m app.trust initialize") == 1
    assert script.index("python -m app.trust initialize") < script.index('exec "$@"')
    assert all(variable in script for variable in (
        "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"
    ))
    assert "PORTAL_VALIDATOR_ADDITIONAL_CA_DIRS" in deployment
    assert "PORTAL_VALIDATOR_BROWSER_CA_DIRS" in deployment
    assert "portal-validator-zscaler-ca" in deployment
    assert "/etc/portal-validator/zscaler" in deployment
    assert "portal-validator-additional-ca" not in deployment
    assert "CORPORATE_CA_BUNDLE" not in deployment
    assert "- name: SSL_CERT_FILE" not in deployment
    assert "- name: REQUESTS_CA_BUNDLE" not in deployment


def test_uvicorn_access_log_filter_redacts_sensitive_query_values():
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1234", "GET", "/callback?code=secret-code&state=secret-state", "1.1", 200),
        None,
    )
    assert RedactingFilter().filter(record)
    rendered = record.msg % record.args
    assert "secret-code" not in rendered
    assert "secret-state" not in rendered
    assert "[REDACTED]" in rendered
