"""XBOW validation-benchmarks harness for prometheus.

This package is a self-contained, additive harness for the
`XBOW validation-benchmarks <https://github.com/xbow-engineering/validation-benchmarks>`_
corpus. It does not touch the existing ``prometheus.eval`` oracle
(Juice Shop + PortSwigger mock); the two harnesses are independent
and can be run side-by-side.

Public surface:

  * :class:`XBOWChallenge` — one challenge (id, level, tags, port).
  * :class:`XBOWResult` — one row in the per-run results store.
  * :data:`PILOT` — the curated 5-challenge pilot.
  * :func:`resolve` — look up a list of challenge ids.
  * :func:`fetch_challenge` / :func:`build_challenge` /
    :func:`start_challenge` / :func:`stop_challenge` /
    :func:`generate_unique_flag` — the build/start/stop primitives.
  * :func:`prometheus.eval.xbow.flag_watch.watch` — verdict from
    the agent's artifacts.
  * :func:`make_run_id` / :func:`run_dir` / :func:`append_row` /
    :func:`write_report` — the results store.
  * :func:`prometheus.eval.xbow.runner.main` — the CLI entry point.

Entry point is wired into ``prometheus.interface.main`` so users can
type ``prometheus xbow list`` / ``prometheus xbow run ...`` / etc.
"""

from __future__ import annotations

from prometheus.eval.xbow.challenges import (
    BY_ID,
    PILOT,
    XBOWChallenge,
    resolve,
)
from prometheus.eval.xbow.results import (
    DEFAULT_ROOT,
    XBOWResult,
    append_row,
    make_run_id,
    run_dir,
    write_report,
)

__all__ = [
    "BY_ID",
    "DEFAULT_ROOT",
    "PILOT",
    "XBOWChallenge",
    "XBOWResult",
    "append_row",
    "make_run_id",
    "resolve",
    "run_dir",
    "write_report",
]
