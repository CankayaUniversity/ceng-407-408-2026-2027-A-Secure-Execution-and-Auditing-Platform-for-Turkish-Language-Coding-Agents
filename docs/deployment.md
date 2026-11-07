# Docker Deployment and Verification

This guide covers the read-only README demo on the `prototype_v1` branch. The demo starts the Gateway and Executor, runs a mock Agent through the permit flow, and verifies SQLite persistence across service restarts.

## 1. Check prerequisites

Install Git, Python 3.11, and Docker with the Compose plugin. The installed Compose version must support `up --wait` and `--wait-timeout`. On macOS, start Docker Desktop. On Windows, run the Bash commands below in a WSL 2 distribution with Docker Desktop integration enabled. On Linux, start Docker Engine.

```bash
git --version
python3.11 --version
docker compose version
docker info --format '{{.OSType}}'
```

The last command should print `linux`. The first build needs access to the base image and Python package indexes. The host-side demo runner uses only the Python standard library. Application dependencies are installed in the images, and the mock Agent requires no model API key.

## 2. Verify a clean deployment

Clone the branch into a new directory and run the demo from the repository root.

```bash
git clone --branch prototype_v1 --single-branch https://github.com/CankayaUniversity/ceng-407-408-2026-2027-A-Secure-Execution-and-Auditing-Platform-for-Turkish-Language-Coding-Agents.git secure-coding-agent
cd secure-coding-agent
docker compose --profile demo config --quiet
python3.11 scripts/run_demo.py
```

The runner creates a uniquely named `secure-demo-...` Compose project with fresh named volumes. Docker assigns an available loopback port to the Gateway. A successful run exits with status 0 and prints the following status messages in Turkish.

```text
Temiz Compose projesi secure-demo-<id>
Gateway ve Executor hazır.
Permit, ağ, mount ve cgroup kontrolleri geçti.
İmzalı okuma, maskeleme, audit ve graph bağlantıları doğrulandı.
Restart sonrası graph ve nonce kayıtları duruyor. Log kontrolü geçti.
```

| Check | Expected result |
| --- | --- |
| Service startup | `keygen` generates the signing keys and exits successfully. The Gateway and Executor pass their health checks. |
| Permit enforcement | A well-formed README read sent to the Executor's `/execute` endpoint from inside its container returns HTTP `403` when the permit is omitted. The equivalent read succeeds with a permit signed by the Gateway. |
| Container isolation | The Agent cannot reach the Executor port directly and has no workspace mount. The runner also checks the Executor's external IPv4 access, filesystem mounts, Docker socket access, and CPU, memory, and process limits. |
| Provenance and nonce persistence | The runner reads the `DERIVED_FROM` and `EXPOSED_TO_AGENT` edges for the tool result. After restarting the Gateway and Executor, it verifies that those edges and the consumed nonce count are unchanged. |
| Redaction and logs | The Agent receives `API_KEY=[REDACTED]` in place of the synthetic secret. The runner checks the Agent output and Docker logs for the unredacted test value and the private key header. |

By default, the runner removes the demo project and its volumes after a successful run. It preserves a failed deployment for inspection and prints its project name.

## 3. Inspect the services and SQLite records

Use `--keep` to retain the demo resources after verification.

```bash
python3.11 scripts/run_demo.py --keep
```

Replace the example value of `PROJECT` with the project name printed by the runner. Set `DEMO_GATEWAY_PORT=0` to match the runner's Compose configuration.

```bash
PROJECT='secure-demo-<id>'
export DEMO_GATEWAY_PORT=0
docker compose -p "$PROJECT" --profile demo ps -a
```

Expect `keygen` to show `Exited (0)` and both `gateway` and `executor` to show `healthy`. The Agent runs as a one-off container and is removed after completion.

The Gateway initializes the provenance graph during startup and stores it in SQLite. The Executor keeps a separate SQLite ledger of consumed permit nonces.

| Data | Service | Container path | Named volume |
| --- | --- | --- | --- |
| Audit events | `gateway` | `/app/data/audit.db` | `audit_data` |
| Provenance graph | `gateway` | `/app/data/audit-provenance.db` | `audit_data` |
| Consumed permit nonces | `executor` | `/app/state/nonce.db` | `executor_state` |

Query the graph from inside the Gateway using a read-only SQLite connection. A single successful demo run produces one `DERIVED_FROM` edge and one `EXPOSED_TO_AGENT` edge.

```bash
docker compose -p "$PROJECT" --profile demo exec -T gateway python -c '
import sqlite3
from contextlib import closing

with closing(sqlite3.connect("file:/app/data/audit-provenance.db?mode=ro", uri=True)) as db:
    for edge_type, count in db.execute(
        "SELECT edge_type, COUNT(*) FROM provenance_edges GROUP BY edge_type ORDER BY edge_type"
    ):
        print(edge_type, count)
'
```

The Executor listens on the internal Compose network. It mounts the public verification key read-only through `verifier_keys`. The Gateway mounts the private signing key read-only through `issuer_keys`.

## 4. Troubleshoot and clean up

If the runner fails during startup, set `PROJECT` to the printed project name and inspect the same deployment.

```bash
docker compose -p "$PROJECT" --profile demo ps -a
docker compose -p "$PROJECT" --profile demo logs --no-color --tail=50 keygen executor gateway
```

An `Exited (1)` status on `keygen` indicates that key initialization failed. Once `keygen` completes, inspect the Executor and Gateway logs for startup errors. For a build failure, run `docker compose -p "$PROJECT" --profile demo build` directly to see the build output.

Remove the demo project and its volumes when inspection is complete.

```bash
docker compose -p "$PROJECT" --profile demo down --volumes
```

The `--volumes` flag deletes the demo's SQLite databases and generated keys. To stop and remove the containers while preserving those records, run `down` without that flag.
