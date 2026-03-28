# rule/

This folder stores **security-policy rule sets** in JSON format.  
Each file targets a specific container runtime or boot-service type
detected by jibrilcon.

| File name                | Applies to…  |
| ------------------------ | ------------ |
| `docker_config_rules.json`   | Docker JSON specs & systemd units |
| `podman_config_rules.json`   | Podman ``containers.conf`` + units |
| `lxc_config_rules.json`      | LXC config files                   |
| _(future)_ `k8s_rules.json`  | K8s / K3s manifests (road-map)     |

---

## Rule document schema

```jsonc
{
  "id": "privileged-container",   // (string) unique within the file
  "severity": "alert",            // alert | warning | info
  "description": "Container runs with --privileged flag",
  "logic": "and",                 // how to combine 'conditions'
  "conditions": [
    { "field": "privileged", "operator": "equals", "value": true },
    { "field": "user",        "operator": "equals", "value": "root" }
  ]
}
```
  - id – Short snake-case identifier used in the final report.
  - severity – How risky the finding is.
  - description – Shown to humans; keep it actionable.
  - logic – Combine multiple conditions: "and" (all pass) or
"or" (any pass).
  - conditions – Array of atomic checks.

---

## Nested rule groups

For more complex logic you may nest rule groups:

```jsonc
"conditions": [
  {
    "logic": "or",
    "conditions": [
      { "field": "cap_add", "operator": "contains", "value": "SYS_ADMIN" },
      { "field": "privileged", "operator": "equals", "value": true }
    ]
  },
  { "field": "readonly_rootfs", "operator": "equals", "value": false }
]
```

---

## Supported operators

| Operator       | Behaviour *(A = field, B = rule value)* |
| -------------- | --------------------------------------- |
| `equals`       | `A == B`                                |
| `not_equals`   | `A != B`                                |
| `contains`     | `B` found in `A` (str/list)             |
| `not_contains` | `B` **not** found in `A`                |
| `in`           | `A` member of list `B`                  |
| `not_in`       | `A` **not** member of list `B`          |
| `regex_match`  | Python `re` *match* (`A` → string)      |
| `exists`       | field present (value ignored)           |
| `not_exists`   | field missing                           |
| `gt` / `gte`   | numeric `>` / `≥`                       |
| `lt` / `lte`   | numeric `<` / `≤`                       |

Unknown operators are skipped and a warning is logged during scan.

---

## Writing new rules

  1. Pick the right JSON file for your runtime (or create a new one).
  2. Keep `id` unique and descriptive – it becomes part of the report path.
  3. Prefer one risk per rule; break large checks into smaller logical
units for better remediation hints.
  4. Use `regex_match` sparingly; string equality is faster and clearer.
  5. Commit rule files alongside unit tests that hit both the pass and
fail paths.

---

## Extending the DSL

Need a brand-new operator?
  1. Add a helper in `util/rules_engine.py`, e.g. `_within_range(a, b)`.
  2. Register it in `_OPERATOR_MAP` – key must match the string you put in
rule JSON.
  3. Document it here and add tests under `tests/test_rules_engine.py`.

DSL complexity is intentionally kept small; challenge your use-case
before adding heavy logic.

---

## Road-map

  - YAML rule syntax (optional for readability)
  - K8s / K3s workload policies
  - Context-aware rules (cross-container correlation)

---

## Rule Reference

Complete list of all built-in rules, grouped by scanner and sorted by severity (descending).

### Docker

| ID | Type | Severity | Description |
| -- | ---- | -------- | ----------- |
| `privileged` | alert | 9.0 | Container is running in privileged mode |
| `host_pid_namespace` | alert | 8.5 | Container shares the host's process namespace |
| `host_network_namespace` | alert | 8.0 | Container shares the host's network namespace |
| `dangerous_capabilities_added` | alert | 8.0 | Container has dangerous kernel capabilities added |
| `host_ipc_namespace` | alert | 7.5 | Container shares the host's IPC namespace |
| `runs_as_root` | alert | 6.0 | Container launched by a systemd service without a non-root User directive |
| `apparmor_disabled` | warning | 6.0 | AppArmor profile is set to unconfined |
| `binds_not_readonly` | warning | 5.0 | At least one bind mount is not readonly |
| `seccomp_disabled` | warning | 5.0 | Seccomp profile is explicitly disabled (seccomp=unconfined) |
| `cap_drop_missing` | warning | 5.0 | No capabilities explicitly dropped |
| `readonly_rootfs_missing` | warning | 4.0 | Readonly root filesystem is not enabled |

### LXC

| ID | Type | Severity | Description |
| -- | ---- | -------- | ----------- |
| `missing_uidmap` | alert | 8.0 | Missing unprivileged UID map (uidmap not set) |
| `missing_gidmap` | alert | 8.0 | Missing unprivileged GID map (gidmap not set) |
| `uidmap_format_invalid` | alert | 8.0 | UID map format invalid (should be '0 <non-zero> <non-zero>') |
| `gidmap_format_invalid` | alert | 8.0 | GID map format invalid (should be '0 <non-zero> <non-zero>') |
| `mount_proc_dangerous` | alert | 8.0 | Mounting /proc is dangerous |
| `mount_sys_dangerous` | alert | 8.0 | Mounting /sys is dangerous |
| `host_network` | alert | 7.5 | Container shares the host network namespace |
| `cap_drop_missing` | alert | 7.0 | No capabilities are dropped (lxc.cap.drop not set) |
| `mount_run_dangerous` | alert | 7.0 | Mounting /run is dangerous |
| `runs_as_root` | alert | 7.0 | LXC container is running as root |
| `mount_dev_should_be_ro` | warning | 7.0 | Mounting /dev (or subpaths) should be readonly |
| `apparmor_disabled` | warning | 6.0 | AppArmor profile is set to unconfined |
| `mount_usr_should_be_ro` | warning | 5.5 | Mounting /usr should be readonly |

### Podman

| ID | Type | Severity | Description |
| -- | ---- | -------- | ----------- |
| `has_cap_sys_admin` | alert | 9.0 | Bounding set includes CAP_SYS_ADMIN (privileged) |
| `host_pid_namespace` | alert | 8.5 | Container shares the host PID namespace |
| `host_network_namespace` | alert | 8.0 | Container shares the host network namespace |
| `dangerous_caps_present` | alert | 8.0 | Container has dangerous kernel capabilities |
| `host_ipc_namespace` | alert | 7.5 | Container shares the host IPC namespace |
| `runs_as_root` | alert | 7.0 | Container runs as root (UID 0) |
| `service_user_missing` | alert | 6.0 | Systemd service unit does not set a non-root User directive |
| `seccomp_disabled` | warning | 6.0 | Seccomp profile is not defined |
| `binds_not_readonly` | warning | 5.0 | Bind mounts exist that are not readonly |
| `readonly_rootfs_missing` | warning | 4.0 | Readonly root filesystem is not enabled |
