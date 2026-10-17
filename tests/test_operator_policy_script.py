"""The optional operator helper never infers identities from browser sessions."""

import json
import os
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "apply_auth_policy.sh"


def run_helper(tmp_path, arguments, *, enabled=True):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "oc-calls.log"
    oc = bin_dir / "oc"
    if enabled:
        oc.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$OC_CALL_LOG\"\n"
                      "case \" $* \" in *' -o yaml '*) printf 'kind: ConfigMap\\n' ;; esac\n",
                      encoding="utf-8")
        oc.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "OC_CALL_LOG": str(log)}
    process = subprocess.run(["bash", str(SCRIPT), *arguments], text=True, capture_output=True,
                             env=env, timeout=20, check=False)
    return process, log.read_text(encoding="utf-8") if log.exists() else ""


def policy_file(tmp_path, *, host="portal.test", identity="identity.test"):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1, "policies": [{
        "id": "approved", "portal_hosts": [host], "authentication_hosts": [identity],
    }]}), encoding="utf-8")
    return path


def test_preview_does_not_mutate_deployment(tmp_path):
    policy = policy_file(tmp_path)
    result, calls = run_helper(tmp_path, ["sandbox", str(policy)])
    assert result.returncode == 0, result.stderr
    assert "Dry-run only" in result.stdout
    assert "get deployment portal-validator" in calls
    assert "set env" not in calls and "set volume" not in calls and "apply" not in calls
    assert "portal.test" not in result.stdout and "identity.test" not in result.stdout


def test_apply_mounts_read_only_policy_without_printing_hosts(tmp_path):
    policy = policy_file(tmp_path)
    result, calls = run_helper(tmp_path, ["sandbox", str(policy), "--apply"])
    assert result.returncode == 0, result.stderr
    assert "create configmap portal-validator-auth-policies" in calls
    assert "set volume deployment/portal-validator" in calls
    assert "--read-only" in calls
    assert "set env deployment/portal-validator" in calls
    assert "PORTAL_VALIDATOR_AUTH_POLICIES_FILE=" in calls
    assert "rollout status deployment/portal-validator" in calls
    assert "portal.test" not in result.stdout and "identity.test" not in result.stdout


@pytest.mark.parametrize("host", ["portal.example", "*.portal.test", "portal.test/evil"])
def test_example_and_non_exact_hosts_are_refused(tmp_path, host):
    policy = policy_file(tmp_path, host=host)
    result, calls = run_helper(tmp_path, ["sandbox", str(policy), "--apply"])
    assert result.returncode != 0
    assert "create configmap" not in calls and "set volume" not in calls


def test_invalid_schema_refuses_apply(tmp_path):
    file = tmp_path / "policy.json"
    file.write_text('{"version":1,"policies":[]}', encoding="utf-8")
    result, calls = run_helper(tmp_path, ["sandbox", str(file), "--apply"])
    assert result.returncode != 0 and not calls
