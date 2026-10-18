"""Run in a final production/debug image with arbitrary UID and read-only root.

Mount this script read-only and override ENTRYPOINT with Python to create a
disposable local CA, then exercise the real entrypoint. No corporate data is
needed. Set RELEASE_SMOKE_DEBUG=true to check the debug startup command; set
RELEASE_SMOKE_PUBLIC_HTTPS=true for an additional strict public HTTPS check.
"""
import json
import os
import ssl
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread


root = Path(tempfile.mkdtemp(prefix="portal-release-smoke-", dir="/tmp"))
enterprise = root / "enterprise"
enterprise.mkdir()


def openssl(*arguments):
    subprocess.run(["openssl", *arguments], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-batch",
        "-keyout", str(root / "root.key"), "-out", str(enterprise / "root.crt"),
        "-days", "1", "-subj", "/CN=Disposable Portal Release Test Root",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
openssl("req", "-newkey", "rsa:2048", "-nodes", "-batch",
        "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"),
        "-subj", "/CN=localhost")
(root / "server.ext").write_text(
    "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
    "basicConstraints=critical,CA:FALSE\n"
    "keyUsage=critical,digitalSignature,keyEncipherment\n"
    "extendedKeyUsage=serverAuth\n"
    "subjectKeyIdentifier=hash\n"
    "authorityKeyIdentifier=keyid,issuer\n", encoding="utf-8",
)
openssl("x509", "-req", "-in", str(root / "server.csr"),
        "-CA", str(enterprise / "root.crt"), "-CAkey", str(root / "root.key"),
        "-CAcreateserial", "-out", str(root / "server.crt"),
        "-days", "1", "-extfile", str(root / "server.ext"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<title>Strict TLS release fixture</title><main>Healthy read-only page</main>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(root / "server.crt", root / "server.key")
server.socket = tls.wrap_socket(server.socket, server_side=True)
thread = Thread(target=server.serve_forever, daemon=True)
thread.start()
env = os.environ.copy()
env.update({
    "PORTAL_VALIDATOR_MANAGED_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
    "PORTAL_VALIDATOR_ADDITIONAL_CA_DIRS": str(enterprise),
    "PORTAL_VALIDATOR_BROWSER_CA_DIRS": str(enterprise),
    "RELEASE_SMOKE_TLS_ORIGIN": f"https://localhost:{server.server_port}",
})
runtime = r'''
import importlib.metadata as m
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.request import urlopen
from playwright.sync_api import sync_playwright
from app.build_info import build_diagnostics
from app.version import VALIDATOR_VERSION

print("RUNTIME_UID=", os.getuid(), sep="", flush=True)
assert os.getuid() == 1000820000
assert os.environ["HOME"] == "/tmp/portal-validator-home"
expected_bundle = os.environ["HOME"] + "/.portal-validator/ca-bundle.crt"
for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
    assert os.environ[name] == expected_bundle
identity = build_diagnostics()
print("BUILD_IDENTITY=" + json.dumps(identity), flush=True)
assert identity["version"] == "1.13.0"
# An explicitly selected, uncommitted release snapshot must be compared with
# the operator's expected hashes rather than falsely claiming a Git revision.
snapshot_path = os.getenv("RELEASE_SMOKE_SOURCE_HASHES")
if snapshot_path:
    from app.build_info import SOURCE_ROOT, source_hashes
    expected = json.loads(Path(snapshot_path).read_text())
    manifest = json.loads((SOURCE_ROOT / "build-info.json").read_text())
    assert expected and source_hashes(SOURCE_ROOT) == manifest["source_sha256"] == expected
    assert identity["git_commit"] is None
    assert identity["source_integrity"]["status"] == "UNVERIFIED"
    print("REVIEWED_SOURCE_SNAPSHOT_MATCH=true", flush=True)
else:
    assert identity["source_integrity"]["status"] == "VERIFIED"
print("PLAYWRIGHT_VERSION=" + m.version("playwright"), flush=True)
assert m.version("playwright") == "1.63.0"
packages = {}
for record in Path("/usr/lib/apk/db/installed").read_text().split("\n\n"):
    fields = dict(line.split(":", 1) for line in record.splitlines() if ":" in line)
    if fields.get("P", "").startswith(("glibc", "python-3.14", "busybox", "libxml2", "libssh2", "pcre2", "libnss", "zlib")):
        packages[fields["P"]] = fields.get("V")
print("APK_VERSIONS=" + json.dumps(packages), flush=True)
status = json.loads(Path(os.environ["PORTAL_VALIDATOR_TRUST_STATUS"]).read_text())
assert status["enterprise_roots"] == len(status["nss_nicknames"]) == 1
subprocess.run(["certutil", "-L", "-d", "sql:" + os.environ["CHROMIUM_NSS_DB"]], check=True)
with urlopen(os.environ["RELEASE_SMOKE_TLS_ORIGIN"], timeout=30) as response:
    assert response.status == 200
print("PYTHON_STRICT_LOCAL_TLS=true", flush=True)
with sync_playwright() as p:
    print("CHROMIUM_EXECUTABLE=" + p.chromium.executable_path, flush=True)
    assert Path(p.chromium.executable_path).is_file()
    browser = p.chromium.launch(headless=True)
    print("CHROMIUM_VERSION=" + browser.version, flush=True)
    try:
        page = browser.new_page()
        response = page.goto(os.environ["RELEASE_SMOKE_TLS_ORIGIN"], wait_until="domcontentloaded", timeout=30000)
        assert response.status == 200
        assert page.title() == "Strict TLS release fixture"
        print("CHROMIUM_STRICT_LOCAL_NSS_TLS=true", flush=True)
        if os.getenv("RELEASE_SMOKE_PUBLIC_HTTPS") == "true":
            response = page.goto("https://google.com", wait_until="domcontentloaded", timeout=30000)
            assert response.status == 200
            print("PUBLIC_HTTPS_STATUS=" + str(response.status), flush=True)
            print("PUBLIC_HTTPS_TITLE=" + page.title(), flush=True)
    finally:
        browser.close()
log_path = Path("/tmp/portal-release-uvicorn.log")
log_stream = log_path.open("w")
command = ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips=*"]
if os.getenv("RELEASE_SMOKE_DEBUG") == "true":
    command = ["python", "-m", "debugpy", "--listen", "0.0.0.0:5678", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--reload"]
process = subprocess.Popen(command, stdout=log_stream, stderr=subprocess.STDOUT)
try:
    deadline = time.monotonic() + 60
    while True:
        try:
            with urlopen("http://127.0.0.1:8080/healthz?opaque=release-fixture-secret", timeout=2) as response:
                health = json.load(response)
            break
        except OSError:
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Final image application startup failed")
            time.sleep(0.2)
    assert health == {"status": "ok", "version": VALIDATOR_VERSION}
    with urlopen("http://127.0.0.1:8080/api/diagnostics/build", timeout=10) as response:
        assert json.load(response) == identity
    print("HTTP_HEALTH=" + json.dumps(health), flush=True)
finally:
    process.terminate()
    process.wait(timeout=30)
    log_stream.close()
log_text = log_path.read_text()
assert "release-fixture-secret" not in log_text
assert "Logging error" not in log_text
assert "GET /healthz HTTP/1.1" in log_text
assert "Application shutdown complete." in log_text
assert process.returncode in (0, -15), process.returncode
print("REDACTED_ACCESS_LOG_VERIFIED=true", flush=True)
print("UVICORN_GRACEFUL_SIGTERM=true", flush=True)
'''
try:
    subprocess.run(["/app/container-entrypoint.sh", "python", "-c", runtime], env=env, check=True)
    subprocess.run(["/app/container-entrypoint.sh", "python", "-m", "app.trust", "status"], env=env, check=True)
    print("REPEATED_ENTRYPOINT_IDEMPOTENT=true", flush=True)
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
