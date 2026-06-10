"""Database utilities for Prometheus."""

from prometheus.db.migrations import apply_prometheus_migrations

__all__ = ["apply_prometheus_migrations"]
