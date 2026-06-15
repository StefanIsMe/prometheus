# Telemetry

This build is **local-only**. The `prometheus.telemetry.posthog` and
`prometheus.telemetry.scarf` modules are no-op stubs and make **no network
calls** to any third-party analytics service.

If you want to send scan events somewhere yourself, write a wrapper module
that imports `prometheus.telemetry.posthog` (and/or `scarf`) and replace the
no-op functions with your own `urllib.request` / `httpx` calls. The call
sites in `prometheus/interface/main.py` and `prometheus/report/state.py` will
then route through your code without further changes.
