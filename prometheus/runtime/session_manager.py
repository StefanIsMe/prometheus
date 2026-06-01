"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from prometheus.config import load_settings
from prometheus.runtime.backends import get_backend
from prometheus.runtime.caido_bootstrap import bootstrap_caido


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, str]],
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry mounts its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container.
    """
    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    entries: dict[str | Path, BaseEntry] = {}
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        entries[ws_subdir] = LocalDir(src=Path(host_path).expanduser().resolve())

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # agent-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    manifest = Manifest(
        entries=entries,
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                "http_proxy": container_caido_url,
                "https_proxy": container_caido_url,
                "ALL_PROXY": container_caido_url,
                "NO_PROXY": "localhost,127.0.0.1",
            },
        ),
    )

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    try:
        client, session = await backend(
            image=image,
            manifest=manifest,
            exposed_ports=(_CONTAINER_CAIDO_PORT,),
        )
    except RuntimeError:
        raise  # Already wrapped with context by docker_client
    except Exception as exc:
        raise RuntimeError(
            f"Failed to create Docker sandbox: {exc}. "
            f"Is Docker running? Check 'docker info' and 'docker ps'."
        ) from exc

    try:
        caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to resolve Caido proxy port inside sandbox: {exc}. "
            f"The container may not have started correctly."
        ) from exc

    host_caido_url = f"http://{caido_endpoint.host}:{caido_endpoint.port}"
    logger.debug("Caido host endpoint resolved: %s", host_caido_url)

    try:
        caido_client = await bootstrap_caido(
            session,
            host_url=host_caido_url,
            container_url=container_caido_url,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to start Caido proxy inside sandbox: {exc}. "
            f"The container may not have started correctly."
        ) from exc

    bundle = {
        "client": client,
        "session": session,
        "caido_client": caido_client,
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. We never want a cleanup failure to prevent the next
    scan from starting; the worst case is a stranded container that
    Docker's normal reaping will catch on next ``docker prune``.

    If the SDK's ``client.delete`` fails (e.g. because the container
    didn't stop in time), we fall back to a direct Docker stop + force
    remove to avoid leaving stale containers behind.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        return

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    try:
        await bundle["client"].delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.warning(
            "cleanup(%s): client.delete raised; attempting forceful container cleanup",
            scan_id,
            exc_info=True,
        )
        _force_cleanup_container(bundle, scan_id)


def _force_cleanup_container(bundle: dict[str, Any], scan_id: str) -> None:
    """Best-effort forceful stop and removal of a sandbox container.

    Used as a fallback when the SDK's ``client.delete`` fails.  Retrieves
    the container ID from the session state and issues direct Docker API
    calls to stop (10 s timeout) and remove (``force=True``) the container.
    """
    container_id: str | None = None
    try:
        session = bundle.get("session")
        if session is not None:
            inner = getattr(session, "_inner", None)
            if inner is not None:
                state = getattr(inner, "state", None)
                if state is not None:
                    container_id = getattr(state, "container_id", None)
    except Exception:
        logger.debug("cleanup(%s): failed to extract container_id", scan_id, exc_info=True)

    if not container_id:
        logger.warning("cleanup(%s): no container_id found; cannot force cleanup", scan_id)
        return

    client = bundle.get("client")
    docker_client = getattr(client, "docker_client", None)
    if docker_client is None:
        logger.warning("cleanup(%s): no docker_client available for force cleanup", scan_id)
        return

    # Stop the container with a 10-second timeout.
    try:
        container = docker_client.containers.get(container_id)
    except Exception:
        logger.info(
            "cleanup(%s): container %s already gone", scan_id, container_id[:12],
        )
        return

    try:
        container.stop(timeout=10)
        logger.info("cleanup(%s): stopped container %s", scan_id, container_id[:12])
    except Exception:
        logger.debug(
            "cleanup(%s): container.stop() raised (may already be stopped)",
            scan_id,
            exc_info=True,
        )

    try:
        container.remove(force=True)
        logger.info("cleanup(%s): removed container %s", scan_id, container_id[:12])
    except Exception:
        logger.warning(
            "cleanup(%s): failed to remove container %s; it may need manual reaping",
            scan_id,
            container_id[:12],
            exc_info=True,
        )
