# config/

This folder stores **data-driven helpers** used by jibrilcon before the
actual scanners start.  They are *not* security rules; instead they
describe *where* and *how* to collect raw information from the mounted
root filesystem.

``systemd.json`` is the only file that ships today, but the layout is
designed so new init systems or discovery helpers can be added without
changing Python code.

---

## File list

| File name       | Purpose |
| --------------- | ----------------------------------------------------------- |
| `systemd.json`  | Search paths, filename regex, and field-extraction rules    |
| _(future)_ `openrc.json` | Same idea for OpenRC once implemented |
| _(future)_ `sysvinit.json` | Ditto for classic SysV init scripts |

---

## Common JSON schema

Each discovery file follows the same high-level keys:

```jsonc
{
  "paths": [                       // Absolute paths (strings)
    "/usr/lib/systemd/system",
    "/etc/systemd/system"
  ],

  "file_regex": ".*\\.service$",    // RE2 / Python `re` pattern

  "extraction_patterns": {          // Map[string]string
    "ExecStart": "(?<=ExecStart=).*",
    "User":      "(?<=User=).*"
  }
}
```

 - paths – Directories that will be recursively scanned.
 - file_regex – Only filenames matching this regex are processed.
 - extraction_patterns – A mapping of field name → regex.
The regex is applied to each line of the target file; the first match
wins. Captured text is stored in `ScanContext.init_meta` so runtime
scanners can read it quickly.

---

## How it is used

  - `jibrilcon.init_manager_finder.detect_init_system()` decides which
discovery file is relevant (`systemd.json`, `openrc.json`, …).

  - For systemd images, `collect_systemd_containers()` loads
`systemd.json`, walks every listed path, and applies the
extraction_patterns to each `*.service` file.

  - Parsed data are cached in the global `ScanContext` instance; no JSON
is emitted yet. Actual scanners (Docker, Podman, LXC) consume this
context to cross-link container names and services.

---

## Adding a new discovery helper

  1. Create `<initsystem>.json` in this folder, following the schema
above.

  2. Update `jibrilcon.init_manager_finder._CONFIG_MAP` to map the init
system name to your new file.

  3. Write unit tests `under tests/test_init_discovery_<name>.py`.

No further Python changes should be needed.

---

## Tips for extraction patterns

  - Keep regex **non-greedy** whenever possible (`.*?`) to avoid spilling
over line endings.
  - If a field may appear multiple times, list the most specific pattern
first in `extraction_patterns` and make sure `collect_*()` uses
`break` after the first hit.
  - Remember that systemd service files allow continuation lines with
a backslash (`\`). Strip and join lines before applying regex if you
need to capture very long `ExecStart=` entries.
