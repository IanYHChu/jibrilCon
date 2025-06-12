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
