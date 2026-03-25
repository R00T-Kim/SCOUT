# Contributing to SCOUT

Thank you for your interest in contributing to SCOUT.

## Getting Started

```bash
git clone https://github.com/R00T-Kim/SCOUT.git
cd SCOUT
./scout --help
```

SCOUT is pure Python 3.10+ with **zero pip dependencies** (stdlib only). No virtual environment or `pip install` needed.

## Running Tests

```bash
pytest -q                           # full suite
pytest -q tests/test_inventory.py   # single module
```

## Project Structure

```
src/aiedge/          # core engine (74 modules, ~58k lines)
tests/               # 88 test files
scripts/             # verification & e2e scripts
docs/                # contracts, runbooks, schemas
benchmarks/          # corpus and performance benchmarks
```

## How to Contribute

### Bug Reports

Open an issue with:
- Firmware type (if applicable, no proprietary firmware)
- SCOUT version and Python version
- Full error output or `stage.json` snippet
- Steps to reproduce

### Code Changes

1. Fork and create a feature branch
2. Follow existing code style (no external dependencies)
3. Add tests in `tests/` for new functionality
4. Ensure `pytest -q` passes
5. Every file write in a stage must use `assert_under_dir()` from `path_safety.py`
6. Submit a pull request

### New Pipeline Stages

See [CLAUDE.md](CLAUDE.md#adding-a-new-pipeline-stage) for the stage creation guide.

### Documentation

Docs live in `docs/`. If you update a stage's behavior, update the relevant contract doc.

## Design Principles

- **Zero dependencies**: stdlib only. No pip packages.
- **Evidence-first**: every finding needs file path, offset, hash, and rationale.
- **Deterministic**: same input must produce same output (see `determinism.py`).
- **Path safety**: all artifact paths must stay within the run directory.

## Code of Conduct

Be respectful, constructive, and focused on making firmware analysis better for everyone.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
