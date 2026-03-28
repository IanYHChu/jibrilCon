# util/

Utility helpers that are *runtime-agnostic* and shared by both the
orchestration layer and every scanner module.  No code in this package
should ever call external processes or make network connections.

---

## Module list

| File / Sub-package       | Responsibility |
| ------------------------ | -------------- |
| `config_loader.py`       | Lazy-load JSON helper files under `config/`, returns immutable `dict` copies |
| `context.py`             | Thread-safe **ScanContext** object passed to all scanners |
| `error_helpers.py`       | Wrap expected I/O exceptions in a soft `SoftIOError` wrapper |
| `logging_utils.py`       | One-shot root-logger initialisation (`colour`, level, format) |
| `path_utils.py`          | Secure path traversal helpers for a mounted rootfs |
| `report_writer.py`       | Write pretty JSON or Gzip-compressed JSON to disk |
| `rules_engine.py`        | Evaluate JSON DSL rules (`equals`, `regex_match`, …) |
| `scanner_loader.py`      | Discover and import `scanners/*.py` modules in priority order |
| `summary_utils.py`       | Merge individual scanner findings into the final report |
| _(future)_ `cache_utils.py` | Cross-scan caching (planned for OCI blobs) |

Each module is **self-contained**: no circular imports, and public APIs
are type-annotated (PEP-484).

---

## Design principles

1. **Pure-Python, stdlib only** – keeps deployment trivial.
2. **Import-cheap** – modules do *not* perform heavy work at import time;
   caching and I/O happen lazily on first use.
3. **Thread safety** – shared state lives in `context.ScanContext`; all
   mutations must hold `ctx.lock`.
4. **Immutable returns** – helpers that return `dict` / `list` expose
   *copies* so callers cannot corrupt cached data inadvertently.
5. **Clear logging** – every helper logs via `logging_utils.get_logger()`
   with a stable prefix so `grep` works.

---

## Adding a new util helper

1. Create `<name>_utils.py` in this folder.
2. Export **only** the symbols that form your public API; prefix private
   helpers with an underscore.
3. Add a short docstring header:

   ```python
   """
   <name>_utils.py
   ===============
   One-line purpose statement.

   Key functions
   -------------
   foo() – short desc
   bar() – short desc
   """
   ```

4. Write unit tests in `tests/test_<name>_utils.py`.
5. Update the module list table in this README.

---

## Logging conventions

```python
from util.logging_utils import get_logger
logger = get_logger(__name__)

logger.debug("Opening %s", path)
logger.warning("Fallback to default value: %s", value)
```

---

## Error handling

  - Raise `SoftIOError` (wraps `OSError`, `JSONDecodeError`, …) for
recoverable issues – scanners may choose to ignore.
  - Raise built-in exceptions (`ValueError`, `TypeError`) for programming
errors; these will fail the scan run and surface in CI.

---

## Road-map

  - `cache_utils.py` – keyed LRU cache for large file reads
  - Move rule-parsing regex compilation into a shared pool
  - Structured logging (JSON) behind an optional CLI flag
