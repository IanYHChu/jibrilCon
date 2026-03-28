# jibrilcon

Static risk scanner for embedded Linux rootfs images. Inspects mounted root filesystems, detects container services started at boot, and evaluates configurations against rule-based policies -- no chroot, no QEMU, no runtime execution.

## Quick Context

- Author: IanYHChu
- License: Apache 2.0
- Python 3.10+ (uses `tomllib` 3.11+, falls back to `tomli`)
- Entry point: `python3 -m jibrilcon <mount_path>`
- No packaging yet (no pyproject.toml / requirements.txt)

## Architecture

```
jibrilcon/              CLI entry & orchestration
  __main__.py           python -m jibrilcon shim
  cli.py                argparse, colored summary, report output
  core.py               init detection -> systemd collection -> parallel scanners -> report
  init_manager_finder.py  ELF heuristic for systemd/sysvinit/openrc detection

scanners/               One module per container runtime
  docker_native.py      Docker (config.v2.json + hostconfig.json)
  lxc.py                LXC (lxc config files + mount entries + lxc-monitord binary parsing)
  podman.py             Podman (OCI config.json + containers.json)

util/                   Shared helpers
  context.py            ScanContext -- thread-safe shared state across scanners
  scanner_loader.py     Dynamic import + ThreadPoolExecutor for parallel scan
  rules_engine.py       JSON DSL rule engine (13 operators, and/or logic)
  systemd_unit_parser.py  Parse .service files, identify container services
  path_utils.py         Safe symlink resolution with rootfs boundary checks
  config_loader.py      Thread-safe cached JSON config loader
  report_writer.py      Atomic write for .json / .json.gz output
  summary_utils.py      Merge scanner results into final report
  error_helpers.py      SoftIOError for graceful JSON read failures
  logging_utils.py      Root logger init

rule/                   JSON rule definitions
  docker_config_rules.json
  lxc_config_rules.json
  podman_config_rules.json

config/
  systemd.json          systemd unit search paths, keywords, engine detection regex

sample/                 Test rootfs fixtures (11 scenarios)
  rootfs_docker_rootful_01/   Default docker data-root
  rootfs_docker_rootful_02/   Custom docker data-root (/data/docker)
  rootfs_docker_rootless_01/  Multi-user rootless docker
  rootfs_lxc_default_01/      Default /var/lib/lxc/
  rootfs_lxc_custom_path_01/  Config in /data/lxc/config/ (non-standard)
  rootfs_lxc_custom_exec_arg_01/  -f flag explicit config path
  rootfs_lxc_custom_exec_arg_02/  -f + -s CLI override
  rootfs_podman_rootful_01/   Default podman storage
  rootfs_podman_rootful_02/   Custom graphRoot (/data/containers)
  rootfs_podman_rootless_01/  Multi-user rootless podman
  rootfs_sysv/                sysvinit detection
```

## Key Design Decisions

- LXC scanner MUST walk the entire rootfs (os.walk) because LXC container config paths are not predictable -- they can be compiled into the LXC binary itself, placed in /var/lib/lxc/, /data/lxc/, or any arbitrary location. The lxc-monitord binary is parsed as a heuristic filter (checking if container names appear in the binary's string table), not as a source of config paths. Do NOT optimize away the os.walk or the binary parsing logic -- both are essential for correctness.
- ScanContext is the coordination hub: systemd_unit_parser pre-collects container metadata (which containers boot via systemd, which lack User= directive), and all scanners consume this via ScanContext.
- Scanners read ExecStart/ExecStartPre lines from ScanContext to detect CLI overrides (--config, --rcfile, -f, -s/--define, --module) and deep-merge them over default configs.

## Conventions

- Conversation in Traditional Chinese, code and docs in English
- No emojis in code or docs
- Scanner modules expose: `scan(mount_path: str, context: ScanContext) -> dict`
- Rule files are JSON with structure: `{"rules": [{"id", "type", "description", "logic", "conditions"}]}`
- Sample rootfs files use .bak extension (git-tracked test fixtures)

## Running

```bash
# Scan a mounted rootfs
python3 -m jibrilcon /mnt/target-rootfs

# With JSON output
python3 -m jibrilcon /mnt/target-rootfs -o report.json

# Against a sample fixture
python3 -m jibrilcon sample/rootfs_docker_rootful_01
```
