# Contributing to jibrilcon

Thank you for your interest in contributing to jibrilcon! This document
covers setup, workflow, and coding guidelines.

---

## Getting Started

```bash
# Clone the repository
git clone https://github.com/IanYHChu/jibrilcon.git
cd jibrilcon

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

Requires **Python 3.10+**.

---

## Development Workflow

### Running Tests

```bash
# Full test suite
python3 -m pytest tests/ -v

# With coverage report
python3 -m pytest tests/ --cov=jibrilcon --cov-report=term-missing

# Single test file
python3 -m pytest tests/test_rules_engine.py -v
```

The CI enforces a minimum of **80% code coverage**.

### Linting

```bash
# Check for issues
ruff check src/ tests/

# Check formatting
ruff format --check src/ tests/

# Auto-fix formatting
ruff format src/ tests/
```

### Running a Scan

```bash
# Against a test fixture
python3 -m jibrilcon tests/fixtures/rootfs_docker_rootful_01

# With JSON output
python3 -m jibrilcon /mnt/target-rootfs -o report.json
```

---

## Project Structure

```
src/jibrilcon/
  cli.py                   CLI entry point (UX only)
  core.py                  Orchestrator
  init_manager_finder.py   Init system detection
  scanners/                One module per runtime (docker, podman, lxc)
  util/                    Shared helpers (rules engine, path utils, etc.)
  rules/                   JSON rule definitions
  config/                  Systemd detection patterns

tests/
  conftest.py              Shared fixtures
  test_*.py                Test modules
```

---

## Adding a New Scanner

1. Create `src/jibrilcon/scanners/<runtime>.py`
2. Implement the `scan(mount_path: str, context: ScanContext) -> dict` function
3. Add `src/jibrilcon/rules/<runtime>_config_rules.json`
4. Add tests in `tests/test_scanners_integration.py` or a new test file

See `src/jibrilcon/scanners/README.md` for the full scanner contract.

## Adding a New Rule

1. Add the rule to the appropriate `rules/<runtime>_config_rules.json`
2. Include: `id`, `type`, `severity`, `description`, `logic`, `conditions`,
   `risk`, `remediation`, and `references`
3. Verify with a test case

See `src/jibrilcon/rules/README.md` for the rule DSL documentation.

---

## Coding Guidelines

- **Language**: Code and documentation in English; conversations may use
  Traditional Chinese
- **Imports**: Always use fully qualified paths
  (`from jibrilcon.util.X import Y`)
- **Type hints**: Required on all public function signatures
- **Tests**: Every new feature or bug fix should include tests
- **Commit messages**: Use imperative mood, focus on "why" not "what"

---

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with tests
3. Ensure all checks pass: `pytest`, `ruff check`, `ruff format --check`
4. Open a PR against `main`
5. CI must pass before merge

---

## Reporting Issues

Open an issue on GitHub with:
- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS

---

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0.
