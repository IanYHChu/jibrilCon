# Changelog

All notable changes to this project will be documented in this file.

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
