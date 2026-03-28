# scanners/

This directory hosts **runtime-specific scanner modules**.  
Each module is imported dynamically by `util.scanner_loader` and executed
in a thread-pool worker during a scan run.

Current modules:

| File name          | Container runtime / Target |
| ------------------ | -------------------------- |
| `docker_native.py` | Docker JSON configs + systemd units |
| `podman.py`        | Podman `containers.conf`, systemd units (root / rootless) |
| `lxc.py`           | LXC `*.conf`, mount entries, uid/gid maps |
| _(future)_ `k8s.py`| Kubernetes / K3s manifests |

---

## Module contract

Every scanner **must** expose **two symbols**:

```python
# scanners/myruntime.py

def scan(rootfs: str | Path, ctx: ScanContext) -> list[dict]:
    ...
```
  - priority — Determines execution order; 0–99 reserved for in-tree
modules. Third-party scanners may use 100+.
  - scan() — Performs static analysis and **returns a list of finding
dicts**. Do not write to disk or print to stdout.

## Finding dictionary schema

```python
{
    "rule_id": "privileged-container",
    "severity": "alert",       # alert | warning | info
    "message":  "Runs with --privileged flag",
    "location": "/var/lib/docker/containers/abcd1234/config.v2.json"
}
```

Returned lists are merged by `core.generate_final_report()` under
`report["scanners"][<module_name>]`.

---

## Accessing shared data

Scanners receive a `util.context.ScanContext` instance (`ctx`):
  - `ctx.rootfs` — Absolute path of mounted image
  - `ctx.init_meta` — Pre-parsed data from `config/*.json` (e.g. systemd
`ExecStart`, `User`, capability sets)
  - `ctx.lock` — `threading.RLock` for cross-scanner synchronisation
*(rarely needed; scanners should avoid shared mutations)*

---

## Common helper utilities

Import from `util.*` when possible to avoid duplication:
  - `util.path_utils.safe_read_text()`
  - `util.rules_engine.evaluate_rules()`
  - `util.summary_utils.summarise_binds()`, etc.

---

## Writing a new scanner

  1. Copy `scanners/template_runtime.py` (create one if missing).
  2. Implement `scan()`:
    - Gather raw data (open files only, no `subprocess`).
    - Build a **flat dict** per container / service.
    - Call `util.rules_engine.evaluate_rules()` with your rule file.
  3. Return a list of findings (`dict`) as defined above.
  4. Add `<runtime>_rules.json` under `rule/`.
  5. Add unit tests under `tests/test_<runtime>.py`.
  6. Register docs: update `README.md` tables.

---

### Performance guidelines

  - **File I/O**: Use buffered read (`with open(..., "rb")`) and scan only
needed directories.
  - **Regex**: Pre-compile with `re.compile()` at module import time.
  - **Avoid global state**: Rely on local variables; the thread pool will
re-use module objects across images.

---

## Road-map

  - K8s / K3s scanner (`k8s.py`)
  - OCI image layout scanner (unpacked `blobs/sha256/*`)
  - Cache layer digests to skip duplicate scans
