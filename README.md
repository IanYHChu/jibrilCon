# jibrilcon

**jibrilcon** is a static risk scanner for embedded Linux systems packaged 
as root filesystem images (ext4, squashfs, etc.). It inspects a *mounted* 
root filesystem, detects container services started at boot, and evaluates 
their configurations against rule-based policies – 
**no chroot, no QEMU, no runtime execution**.

---

## Key Features

| Area                      | Details |
| ------------------------- | ------- |
| Init discovery            | `systemd`, `sysvinit`, `openrc` (heuristic ELF scan) |
| Container runtimes        | **Docker**, **Podman**, **LXC**<br>(K8s / K3s coming soon) |
| Rule engine               | JSON DSL – `equals`, `regex_match`, `gt`, `exists`, … |
| Parallel scanning         | Thread-pool executes scanners concurrently |
| Output formats            | Pretty JSON or Gzip-compressed JSON |
| Zero runtime dependency   | Reads files only; nothing inside the image is executed |

---

## Why jibrilcon?

Embedded Linux systems often have strong hardware dependencies, making it difficult even impractical to run the system image in a simulated host environment. Requiring full system boot just to analyze configuration introduces unnecessary cost and complexity. **jibrilcon** uses a static analysis approach: it scans a mounted root filesystem directly, analyzing files without executing any binaries. This approach avoids runtime dependencies and minimizes impact on the host.

Additionally, embedded systems usually lack an interface for user interaction — all services are launched automatically at boot time. Instead of waiting for user-triggered actions or relying on runtime behavior, **jibrilcon** analyzes system boot configurations (e.g., systemd service files) to identify which containers are started at boot, and focuses its security analysis on those services.

---

## What does jibrilcon do?

- Mounts a Linux rootfs image on an host machine
- Scans for insecure or privileged container configurations across:
  - LXC
  - Docker
  - Podman
- Supports JSON-based rule definitions for easy customization
- Reports risky configurations such as:
  - Containers running as root
  - Dangerous or writable mounts
  - Overuse of privileged flags or capabilities

---

## How it works

1. You mount your embedded Linux rootfs (e.g., at `/mnt/target-rootfs`)
2. You run `jibrilcon` and point it to the mount path
3. It dynamically loads all scanner modules from `scanners/`
4. Each scanner extracts container configuration data and applies static rules
5. A final report is generated with alerts, warnings, and summaries

---

## Output

The output is a JSON report containing:
- Violations detected per container or service
- Alert/warning counts by scanner
- Summarized findings across all modules

---

## Example Usage

```bash
# Basic scan with colored console output
$ python3 -m jibrilcon /mnt/target-rootfs

# Disable colored output (useful for logs or file redirection)
$ python3 -m jibrilcon /mnt/target-rootfs --no-color

# Save report as plain JSON
$ python3 -m jibrilcon /mnt/target-rootfs --output ./scan-report.json

# Save report as compressed Gzip JSON
$ python3 -m jibrilcon /mnt/target-rootfs --output ./scan-report.json.gz
```

- If `--output` ends with `.json`, the report is saved as a plain JSON file.
- If `--output` ends with `.json.gz`, the report is saved as a Gzip-compressed JSON file.
- If `--output` is not specified, the report is printed to the console.
- Use `--no-color` to disable ANSI color in terminal output (useful for CI pipelines or log files).
  - If `--output` is specified, colored console output is automatically disabled (equivalent to `--no-color`). This prevents ANSI escape codes from being written into the output file.

---

## Project Structure

```
jibrilcon/            CLI entry & orchestration
scanners/           One module per runtime (priority-based)
util/               Shared helpers (rules_engine, path_utils, …)
rule/               JSON rule sets
config/             systemd / init discovery data
```

---

## Extending jibrilcon

Add a new runtime scanner
  1. Create scanners/<runtime>.py
  2. Expose:
    ```python
    def scan(rootfs: str, ctx: ScanContext) -> list[dict]: ...
    ```
  3. Add rule/<runtime>_rules.json with your policies.

Add a new rule operator
  1. Implement a _myop(a, b) -> bool helper in util/rules_engine.py.
  2. Register it in _OPERATOR_MAP.
  3. Add unit tests and docs.

---

## Roadmap

  - Kubernetes / K3s manifest scanner
  - YAML rule syntax with logical operators
  - SBOM correlation (packages ↔ containers)
