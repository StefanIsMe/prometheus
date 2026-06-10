"""Run directory path helpers."""

from __future__ import annotations

from pathlib import Path


RUNS_DIR_NAME = "prometheus_runs"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"

_configured_runs_base: Path | None = None


def configure_runs_dir(path: str | Path) -> None:
    """Set a fixed base directory for all run directories.

    Call once at startup (from TUI or CLI entry point) so that
    scans from all entry points land in the same place.
    """
    global _configured_runs_base
    _configured_runs_base = Path(path).resolve()


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    if _configured_runs_base is not None:
        return _configured_runs_base / RUNS_DIR_NAME / run_name
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME / run_name


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME
