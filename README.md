# jibrilcon

**jibrilcon** is a static risk scanner for embedded Linux systems packaged
as root filesystem images (ext4, squashfs, etc.). It inspects a *mounted*
root filesystem, detects container services started at boot, and evaluates
their configurations against rule-based policies --
**no chroot, no QEMU, no runtime execution**.

---

## Key Features

| Area | Details |
| --- | --- |
| Init discovery | `systemd`, `sysvinit`, `openrc` (heuristic ELF scan) |
| Container runtimes | **Docker**, **Podman**, **LXC** |
| Rule engine | JSON DSL with 14 operators (`equals`, `regex_match`, `not_regex_match`, `gt`, `exists`, ...) |
| Framework mapping | MITRE ATT&CK, CIS Docker Benchmark, NIST SP 800-190 |
| Parallel scanning | Thread-pool executes scanners concurrently |
| Output formats | JSON or Gzip-compressed JSON |
| Zero runtime dependency | Reads files only; nothing inside the image is executed |

---

## Why jibrilcon?

Embedded Linux systems often have strong hardware dependencies, making it
difficult or impractical to run the system image in a simulated host
environment. Requiring full system boot just to analyze configuration
introduces unnecessary cost and complexity. **jibrilcon** uses a static
analysis approach: it scans a mounted root filesystem directly, analyzing
files without executing any binaries.

Additionally, embedded systems usually lack an interface for user
interaction -- all services are launched automatically at boot time. Instead
of relying on runtime behavior, **jibrilcon** analyzes system boot
configurations (e.g., systemd service files) to identify which containers
are started at boot, and focuses its security analysis on those services.

---

## Installation

```bash
# Requires Python 3.10+
pip install -e ".[dev]"
```

---

## Usage

```bash
# Check version
python3 -m jibrilcon --version

# Basic scan with colored console output
python3 -m jibrilcon /mnt/target-rootfs

# Save report as JSON
python3 -m jibrilcon /mnt/target-rootfs -o report.json

# Save report as Gzip-compressed JSON
python3 -m jibrilcon /mnt/target-rootfs -o report.json.gz

# Disable colored output (useful for CI pipelines)
python3 -m jibrilcon /mnt/target-rootfs --no-color

# Adjust scanner parallelism
python3 -m jibrilcon /mnt/target-rootfs --max-workers 4
```

If `--output` is not specified, the report is printed to stdout. Use
`--no-color` to disable ANSI escape codes for log files or CI.

---

## Report Format

### Top-level Structure

```json
{
  "report": [
    {
      "scanner": "docker | podman | lxc",
      "summary": {
        "alerts": 3,
        "warnings": 1
      },
      "results": [
        {
          "container": "my-app",
          "status": "violated | clean",
          "violations": [ "..." ]
        }
      ]
    }
  ],
  "summary": {
    "alerts": 5,
    "warnings": 2,
    "clean": 1,
    "violated": 3,
    "scanners_run": ["docker", "podman", "lxc"]
  }
}
```

| Field | Type | Description |
| --- | --- | --- |
| `report` | array | Per-scanner result blocks |
| `report[].scanner` | string | Scanner module name |
| `report[].summary` | object | Per-scanner alert/warning counts |
| `report[].results` | array | Per-container entries with `status` ("clean" or "violated") |
| `summary` | object | Aggregated counts across all scanners |
| `summary.scanners_run` | array | Names of scanners that executed |

### Violation Entry

Each violation includes actionable context and framework references:

```json
{
  "id": "privileged",
  "type": "alert",
  "severity": 9.0,
  "description": "Container is running in privileged mode",
  "risk": "Grants full access to all host devices and disables most kernel isolation.",
  "remediation": "Remove --privileged flag. Use --cap-add for specific capabilities.",
  "references": {
    "mitre_attack": ["T1611"],
    "cis_docker_benchmark": ["5.4"],
    "nist_800_190": ["4.4"]
  },
  "source": "/var/lib/docker/containers/.../config.v2.json",
  "lines": ["HostConfig.Privileged = True"]
}
```

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Rule identifier |
| `type` | string | `"alert"` or `"warning"` |
| `severity` | float | Risk score from 1.0 (low) to 10.0 (critical), following CVSS v3 qualitative scale |
| `description` | string | Human-readable summary of the finding |
| `risk` | string | Why this configuration is dangerous |
| `remediation` | string | Recommended fix |
| `references` | object | Framework mapping (MITRE ATT&CK, CIS, NIST) |
| `source` | string | Config file path relative to mount point |
| `lines` | array | Specific config entries that triggered the rule |

### Severity Scale

Severity follows the [CVSS v3 qualitative rating](https://www.first.org/cvss/specification-document):

| Score | Rating | Example |
| --- | --- | --- |
| 9.0 -- 10.0 | Critical | Privileged mode, full host access |
| 7.0 -- 8.9 | High | Missing capability drops, user namespace disabled |
| 4.0 -- 6.9 | Medium | Writable bind mounts, PID mode sharing |
| 0.1 -- 3.9 | Low | Informational findings |

### Mapped Frameworks

| Framework | Coverage |
| --- | --- |
| [MITRE ATT&CK (Containers)](https://attack.mitre.org/matrices/enterprise/containers/) | T1611, T1078.003, T1565.001, T1003 |
| [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) | Section 5 (Container Runtime) |
| [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final) | Section 4.4 (Container Risks) |

---

## How It Works

1. Mount an embedded Linux rootfs on the host (e.g., at `/mnt/target-rootfs`)
2. **Init detection** -- identifies systemd / sysvinit / openrc via ELF heuristic
3. **Systemd pre-collection** -- parses `.service` files to find which containers boot via systemd, caching ExecStart/ExecStartPre lines and User directives
4. **Parallel scanning** -- dynamically loads all scanner modules (`docker_native`, `podman`, `lxc`) and runs them in a thread pool
5. **Rule evaluation** -- each scanner extracts config fields and evaluates them against JSON rule definitions
6. **Report generation** -- merges results into a unified report with per-container violations and summary statistics

---

## Project Structure

```
src/jibrilcon/
  __main__.py              python -m jibrilcon entry point
  cli.py                   Argument parsing, colored summary, report output
  core.py                  Orchestrator: init detection -> systemd -> scanners -> report
  init_manager_finder.py   ELF heuristic for init system detection

  scanners/                One module per container runtime
    docker_native.py       Docker (config.v2.json + hostconfig.json)
    lxc.py                 LXC (config files + mount entries + lxc-monitord)
    podman.py              Podman (OCI config.json + containers.json)

  util/                    Shared helpers
    rules_engine.py        JSON DSL rule engine (14 operators, and/or logic)
    context.py             Thread-safe shared state across scanners
    systemd_unit_parser.py Parse .service files, detect container services
    path_utils.py          Safe symlink resolution with rootfs boundary checks
    ...

  rules/                   JSON rule definitions with framework mappings
  config/                  Systemd unit search paths and detection patterns
```

---

## Extending jibrilcon

### Add a new runtime scanner

1. Create `src/jibrilcon/scanners/<runtime>.py`
2. Expose:
   ```python
   def scan(mount_path: str, context: ScanContext) -> dict: ...
   ```
3. Add `src/jibrilcon/rules/<runtime>_config_rules.json` with rule definitions

### Add a new rule operator

1. Implement `_myop(a, b) -> bool` in `src/jibrilcon/util/rules_engine.py`
2. Register it in `_OPERATOR_MAP`

### Add framework mappings to a rule

Include these optional fields in any rule definition:

```json
{
  "severity": 7.0,
  "risk": "Why this is dangerous",
  "remediation": "How to fix it",
  "references": {
    "mitre_attack": ["T1611"],
    "cis_docker_benchmark": ["5.4"],
    "nist_800_190": ["4.4"]
  }
}
```

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
python3 -m pytest tests/ -v

# Lint
ruff check src/ tests/
```

---

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Scan completed successfully (violations may or may not be present) |
| 1 | Runtime error (e.g., permission denied, corrupted config) |
| 2 | Argument error (invalid flag, missing mount path) |
| 130 | Interrupted by user (Ctrl+C / SIGINT) |

---

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
