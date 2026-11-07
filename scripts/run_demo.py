"""Build and verify the signed README demo in a fresh Compose project."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
CANARY = "compose-fixture-canary-7f29d4"

ISOLATION_PROBE = """
import os
import sys
from pathlib import Path

role = sys.argv[1]
assert os.getuid() != 0, "Service must run as non-root."
assert os.statvfs("/app").f_flag & os.ST_RDONLY, "Application mount must be read-only."
assert not Path("/var/run/docker.sock").exists(), "Docker socket is mounted."
assert not os.environ.get("DOCKER_HOST"), "Docker endpoint is configured."
assert not Path("/app/issuer/private.pem").exists(), "Signing key is accessible."
if role == "agent":
    assert not Path("/workspace").exists(), "Agent has direct workspace access."
else:
    assert os.statvfs("/workspace").f_flag & os.ST_RDONLY, "Demo workspace is writable."
    assert Path("/workspace/README.md").is_file(), "Demo workspace is not seeded."

cgroups = Path("/sys/fs/cgroup")
if (cgroups / "cpu.max").exists():
    quota, period = (cgroups / "cpu.max").read_text().split()
    memory = (cgroups / "memory.max").read_text().strip()
    pids = (cgroups / "pids.max").read_text().strip()
else:
    cpu = cgroups / "cpu"
    if not cpu.exists():
        cpu = cgroups / "cpu,cpuacct"
    quota = (cpu / "cpu.cfs_quota_us").read_text().strip()
    period = (cpu / "cpu.cfs_period_us").read_text().strip()
    memory = (cgroups / "memory/memory.limit_in_bytes").read_text().strip()
    pids = (cgroups / "pids/pids.max").read_text().strip()
assert int(quota) / int(period) == (0.5 if role == "agent" else 1.0), "CPU limit mismatch."
assert int(memory) == 256 * 1024 * 1024, "Memory limit mismatch."
assert int(pids) == 64, "Process limit mismatch."
"""

EXECUTOR_PROBE = """
import errno
import json
import socket
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

request = Request("http://127.0.0.1:8001/execute", method="POST",
                  headers={"Content-Type": "application/json"},
                  data=json.dumps({"call": {
                      "task_id": "task-demo-001",
                      "request_id": "direct-without-permit",
                      "tool": "secure_read_file",
                      "arguments": {"path": "README.md"},
                  }}).encode())
try:
    with build_opener(ProxyHandler({})).open(request, timeout=3):
        raise AssertionError("Permitsiz istek reddedilmedi.")
except HTTPError as error:
    with error:
        assert error.code == 403, "Expected permit rejection."
try:
    with socket.create_connection(("192.0.2.1", 443), timeout=2):
        raise AssertionError("Executor has an external IPv4 connection.")
except OSError as error:
    assert error.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM}, (
        "Executor IPv4 isolation could not be confirmed."
    )
"""

AGENT_NETWORK_PROBE = """
import socket
import sys

try:
    with socket.create_connection((sys.argv[1], 8001), timeout=2):
        raise AssertionError("Agent reached the executor directly.")
except OSError:
    pass
"""

GRAPH_PROBE = """
import json
import sqlite3
import sys
from contextlib import closing

with closing(sqlite3.connect("file:/app/data/audit-provenance.db?mode=ro", uri=True)) as db:
    rows = db.execute(
        "SELECT edge_type, target_node_id FROM provenance_edges WHERE source_node_id = ? ORDER BY edge_type",
        ("result:" + sys.argv[1],),
    ).fetchall()
with closing(sqlite3.connect("file:/app/data/audit.db?mode=ro", uri=True)) as db:
    verified = db.execute(
        "SELECT metadata FROM audit_events WHERE request_id = ? AND event_type = 'permit_verification'",
        (sys.argv[1],),
    ).fetchall()
assert any(json.loads(row[0]).get("outcome") == "verified" for row in verified), "Permit verification audit missing."
print(json.dumps(rows))
"""

NONCE_PROBE = """
import sqlite3
from contextlib import closing

with closing(sqlite3.connect("file:/app/state/nonce.db?mode=ro", uri=True)) as db:
    print(db.execute("SELECT count(*) FROM used_nonces").fetchone()[0])
"""


def write_key(path: Path, data: bytes, mode: int) -> None:
    """Write a complete PEM file before exposing its final name."""
    with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            temporary.chmod(mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def init_keys(issuer_dir: Path, verifier_dir: Path) -> None:
    """Initialize the signing pair once and verify the existing pair on reuse."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from secure_agent.security.permit_issuer import load_ed25519_private_key

    private_path = issuer_dir / "private.pem"
    public_path = verifier_dir / "public.pem"
    if private_path.exists():
        key = load_ed25519_private_key(private_path)
    else:
        if public_path.exists():
            raise RuntimeError("Public key exists without its signing key.")
        key = Ed25519PrivateKey.generate()
        write_key(private_path, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ), 0o600)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not public_path.exists():
        write_key(public_path, public, 0o644)
    elif public_path.read_bytes() != public:
        raise RuntimeError("Stored public key does not match the signing key.")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run_demo(*, keep: bool) -> None:
    project = "secure-demo-" + uuid4().hex[:10]
    prefix = [
        "docker", "compose", "--file", str(ROOT / "docker-compose.yml"),
        "--project-name", project, "--profile", "demo",
    ]
    environment = {**os.environ, "DEMO_GATEWAY_PORT": "0"}

    def compose(*arguments: str, timeout: int = 90) -> str:
        completed = subprocess.run(
            [*prefix, *arguments], cwd=ROOT, env=environment, timeout=timeout,
            text=True, capture_output=True, check=False,
        )
        if completed.returncode:
            raise RuntimeError(
                f"Compose adımı başarısız ({arguments[0]}, çıkış {completed.returncode})."
            )
        if arguments[0] in {"run", "logs"}:
            combined = completed.stdout + completed.stderr
            require(CANARY not in combined and "BEGIN PRIVATE KEY" not in combined,
                    "Runtime çıktısında örnek sır veya anahtar izi görüldü.")
        return completed.stdout

    print(f"Temiz Compose projesi {project}", flush=True)
    try:
        compose("build", timeout=600)
        compose("up", "--wait", "--wait-timeout", "60", "gateway", "executor")
        print("Gateway ve Executor hazır.", flush=True)

        compose("exec", "-T", "executor", "python", "-c", ISOLATION_PROBE, "executor")
        compose("exec", "-T", "executor", "python", "-c", EXECUTOR_PROBE)
        compose("run", "--rm", "--no-deps", "-T", "agent",
                "python", "-c", ISOLATION_PROBE, "agent")
        executor_ip = compose("exec", "-T", "executor", "python", "-c",
                              "import socket; print(socket.gethostbyname(socket.gethostname()))").strip()
        compose("run", "--rm", "--no-deps", "-T", "agent",
                "python", "-c", AGENT_NETWORK_PROBE, executor_ip)
        print("Permit, ağ, mount ve cgroup kontrolleri geçti.", flush=True)

        output = compose("run", "--rm", "--no-deps", "-T", "agent")
        result = json.loads(output)
        require(result["stop_reason"] == "model_finished", "Agent görevi tamamlamadı.")
        require(len(result["tool_results"]) == 1, "Bir adet araç sonucu bekleniyor.")
        read = result["tool_results"][0]
        require(read["status"] == "success", "İmzalı README okuması başarısız.")
        require("API_KEY=[REDACTED]" in read["output"] and CANARY not in output,
                "Agent çıktısı maskeleme kontrolünden geçmedi.")
        before = compose("exec", "-T", "gateway", "python", "-c",
                         GRAPH_PROBE, read["request_id"])
        require(
            sorted(json.loads(before)) == sorted([
                ["DERIVED_FROM", "source:" + read["source_id"]],
                ["EXPOSED_TO_AGENT", "agent:task:task-demo-001"],
            ]),
            "Beklenen provenance bağlantıları bulunamadı.",
        )
        nonces = compose("exec", "-T", "executor", "python", "-c", NONCE_PROBE).strip()
        require(int(nonces) == 1, "Tek bir tüketilmiş permit bekleniyor.")
        print("İmzalı okuma, maskeleme, audit ve graph bağlantıları doğrulandı.", flush=True)

        compose("restart", "gateway", "executor")
        compose("up", "--wait", "--wait-timeout", "60", "--no-recreate", "gateway", "executor")
        after = compose("exec", "-T", "gateway", "python", "-c",
                        GRAPH_PROBE, read["request_id"])
        require(before == after, "Restart sonrası graph kaydı farklı.")
        require(nonces == compose("exec", "-T", "executor", "python", "-c",
                                  NONCE_PROBE).strip(), "Restart sonrası nonce kaydı farklı.")
        compose("logs", "--no-color")
        print("Restart sonrası graph ve nonce kayıtları duruyor. Log kontrolü geçti.", flush=True)
    finally:
        if keep or sys.exc_info()[0] is not None:
            print(f"İncelemek için docker compose -p {project} --profile demo ps", flush=True)
            print(f"Temizlemek için docker compose -p {project} --profile demo down --volumes", flush=True)
        else:
            compose("down", "--volumes", "--remove-orphans")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="Keep the isolated demo project.")
    parser.add_argument("--init-keys", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.init_keys:
        init_keys(Path("/app/issuer"), Path("/app/verifier"))
    else:
        try:
            run_demo(keep=args.keep)
        except (RuntimeError, OSError, subprocess.TimeoutExpired, ValueError) as error:
            raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
