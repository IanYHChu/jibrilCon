# Changelog

All notable changes to this project will be documented in this file.

## [1.2.1] - 2026-03-29

### Fixed
- Docker scanner: normalize capability names to uppercase before comparison (could miss dangerous caps like `cap_sys_admin`)
- Docker scanner: handle IPv6 bracketed addresses in bind mount parsing
- Docker scanner: empty image string no longer misclassified as "latest" tag
- Podman scanner: log warning when TOML module config is not a dict
- PDF report: use explicit `None` checks instead of `or` chain to correctly handle scanner count of 0
- Scanner loader: narrow exception handling from bare `Exception` to specific import-related types
- passwd_utils: eliminate TOCTOU race condition; move `UnicodeDecodeError` handling to file iteration
- config_loader: catch `UnicodeDecodeError` from `read_text()`
- violation_utils: use `Path.relative_to()` instead of `os.path.relpath()` to prevent `..` path traversal in source field
- rules_engine: reject rule conditions with missing or empty `field`
- core.py: validate `mount_path`, `max_workers`, and `scanner_timeout` parameters in `run_scan()`
- init_manager_finder: remove redundant `exists()` check after `lstat()` failure
- Scanner ValueError messages now include module name for easier debugging

### Changed
- Extract shared `threadsafe_lru_cache` decorator into `util/cache_utils.py` (was duplicated in `rules_engine.py` and `path_utils.py`)
- Deduplicate test helpers (`_make_context`, `_write_json`, `_write_text`, `_write_binary`, `_fresh_cache`) into `tests/conftest.py`
- Replace timing-based `time.sleep()` in scanner timeout test with `threading.Event` for deterministic behavior
- Add `__main__.py` entry point test coverage

## [1.0.0] - 2026-03-28

### Added
- Docker scanner with 11 security rules (privileged, host namespace isolation, capabilities, seccomp, AppArmor, rootfs, bind mounts)
- Podman scanner with 10 security rules (root user, host namespaces, capabilities, seccomp, rootfs, bind mounts)
- LXC scanner with 13 security rules (ID mapping, mount security, capabilities, AppArmor, networking)
- JSON DSL rule engine with 14 operators and AND/OR logic
- Systemd unit parser for container service detection
- Support for rootful and rootless container discovery
- Framework-mapped output (MITRE ATT&CK, CIS Docker Benchmark, NIST SP 800-190)
- JSON and gzip report output
- Colored terminal summary
- Thread-safe parallel scanning via ThreadPoolExecutor
