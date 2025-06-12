# jibrilcon/  —  Package Overview
This package holds the **command-line interface** and the **orchestration
logic** that binds all runtime scanners together.

The code is *import-safe*: nothing is executed at import time except for
constant definitions and logging setup.  That makes it easy to plug
`jibrilcon` into your own Python tooling if you do not wish to use the
bundled CLI.

---

## Directory Contents

| File / Sub-package        | Purpose |
| ------------------------- | ------------------------------------------------ |
| `__main__.py`             | `python -m jibrilcon` shim – forwards to CLI |
| `cli.py`                  | Parse CLI args, configure logging, call `core.run_scan` |
| `core.py`                 | Detect init system, spawn scanners, merge results |
| `init_manager_finder.py`  | Heuristics for `systemd` / `sysvinit` / `openrc` |
| `context.py`              | Thread-safe `ScanContext` shared by all scanners |
| `scanner_loader.py`       | Dynamically discover `scanners/*.py` modules |
| `__init__.py`             | Lightweight convenience re-exports |

---

## Execution Pipeline

```text
mounted rootfs
      │
      ▼
detect_init_system()         ← init_manager_finder.py
      │
      ├─ collect_systemd_containers()  (systemd only)
      │         └─ fill ScanContext.init_meta
      ▼
run_scan()                   ← core.py
      │
      └─ ThreadPoolExecutor runs scanner modules in parallel
                │
                ├─ scanners/docker_native.py
                ├─ scanners/podman.py
                └─ scanners/lxc.py
      ▼
generate_final_report()      ← util/summary_utils.py
      ▼
JSON / JSON.GZ report        ← cli.py writes to file / stdout
```
Every stage logs its progress; use --log-level debug in the CLI to see
full trace output.

---

## Public API (import usage)
```python
from jibrilcon.core import run_scan
from util.summary_utils import load_report        # Optional helper

report_dict = run_scan("/mnt/rootfs")
print(report_dict["summary"])
```

  - `run_scan(rootfs_path: str | Path, rules_dir: Path | None = None) -> dict`
  - All helper functions are type-annotated (PEP-484).

---

## Adding New Functionality

New scanner module
  1. Drop `<runtime>.py` into `scanners/`
  2. Expose:
    ```python
    def scan(rootfs: str | Path, ctx: ScanContext) -> list[dict]: ...
    ```
  3. Add corresponding rule file under `rule/`
  4. Unit-test under `tests/`

Support a new init system
  1. Create `config/<initsystem>.json` (see `config/systemd.json`)
  2. Update `_CONFIG_MAP` inside `init_manager_finder.py`
  3. Write discovery helper `collect_<initsystem>_containers()`

---

## Roadmap

  - Kubernetes / K3s manifest scanner
  - YAML rule syntax with boolean logic
  - SBOM integration (map packages → container layers)
