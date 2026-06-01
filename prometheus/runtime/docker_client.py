"""prometheusDockerSandboxClient — preserves the image's ENTRYPOINT and adds
NET_ADMIN/NET_RAW capabilities + host-gateway.

The SDK's ``DockerSandboxClient._create_container`` does not expose a hook for
extending ``create_kwargs`` before ``containers.create`` is called. We subclass
and reimplement the method body verbatim from the SDK source, with three
deltas:

1. Drop the SDK's ``entrypoint=["tail"]`` override; supply ``["tail", "-f",
   "/dev/null"]`` as ``command`` instead. This lets our image's
   ``docker-entrypoint.sh`` actually run — without it, ``caido-cli`` never
   starts inside the container and ``bootstrap_caido`` retries against a
   dead port.
2. Append NET_ADMIN/NET_RAW to ``cap_add`` (required by ``nmap -sS`` and
   other raw-socket tools).
3. Add ``host.docker.internal`` → host-gateway to ``extra_hosts`` so the
   agent can reach host-served apps.

Pinned to ``openai-agents==0.14.6``. Bumping the SDK requires
re-merging the parent body. Track upstream for an injection hook.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    _build_docker_volume_mounts,
    _docker_port_key,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
)
from docker.models.containers import Container  # type: ignore[import-untyped, unused-ignore]
from docker.utils import parse_repository_tag  # type: ignore[import-untyped, unused-ignore]


logger = logging.getLogger(__name__)

# Tor SOCKS5 proxy address — reachable from containers via Docker's host-gateway.
_TOR_PROXY = "socks5://host.docker.internal:9050"


def _inject_tor_proxy(
    environment: dict[str, str] | list[str] | None,
) -> dict[str, str]:
    """Return *environment* with every proxy var pointing to Tor.

    session_manager.py seeds ``http_proxy`` / ``https_proxy`` (lowercase)
    to the in-container Caido intercepting proxy.  Many HTTP clients check
    the *lowercase* variant first, so we must override **both** cases to
    avoid tools silently using Caido instead of Tor.

    The intended traffic flow is:  tool → Caido → Tor → internet
    Caido itself must be configured to chain through Tor (done separately
    in caido_bootstrap); the env vars here ensure that *tool* traffic is
    sent to Caido which then delegates to Tor, rather than tools bypassing
    Tor entirely.
    """
    if environment is None:
        env_dict: dict[str, str] = {}
    elif isinstance(environment, list):
        env_dict = dict(e.split("=", 1) for e in environment if "=" in e)
    else:
        env_dict = dict(environment)

    # Override ALL proxy vars — uppercase AND lowercase — to Tor.
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env_dict[key] = _TOR_PROXY
    env_dict["NO_PROXY"] = "localhost,127.0.0.1"

    logger.info("Tor proxy injected (override): %s", _TOR_PROXY)
    return env_dict


class prometheusDockerSandboxClient(DockerSandboxClient):
    async def _create_container(
        self,
        image: str,
        *,
        manifest: Manifest | None = None,
        exposed_ports: tuple[int, ...] = (),
        session_id: uuid.UUID | None = None,
    ) -> Container:
        # ----- BEGIN VERBATIM COPY of DockerSandboxClient._create_container -----
        # SDK ref: src/agents/sandbox/sandboxes/docker.py:1434-1477 (v0.14.6).
        if not self.image_exists(image):
            repo, tag = parse_repository_tag(image)
            try:
                self.docker_client.images.pull(repo, tag=tag or None, all_tags=False)
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to pull Docker image '{image}': {exc}. "
                    f"Check your network or run 'docker pull {image}' manually."
                ) from exc

        if not self.image_exists(image):
            raise RuntimeError(
                f"Docker image '{image}' not found after pull attempt. "
                f"Run 'docker pull {image}' manually to diagnose."
            )
        environment: dict[str, str] | None = None
        if manifest:
            environment = await manifest.environment.resolve()
        # prometheus delta from the SDK body: drop ``entrypoint`` override and
        # supply ``tail -f /dev/null`` as ``command`` so the image's
        # ENTRYPOINT (``docker-entrypoint.sh``) runs setup, then ``exec
        # "$@"`` becomes ``exec tail -f /dev/null`` for the keep-alive.
        # Without this, caido-cli + the in-container CA trust never get
        # initialized.
        create_kwargs: dict[str, Any] = {
            "image": image,
            "detach": True,
            "command": ["tail", "-f", "/dev/null"],
            "environment": environment,
        }
        if manifest is not None:
            docker_mounts = _build_docker_volume_mounts(
                manifest,
                session_id=session_id,
            )
            if docker_mounts:
                create_kwargs["mounts"] = docker_mounts
            if _manifest_requires_fuse(manifest):
                create_kwargs.update(
                    devices=["/dev/fuse"],
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
            elif _manifest_requires_sys_admin(manifest):
                create_kwargs.update(
                    cap_add=["SYS_ADMIN"],
                    security_opt=["apparmor:unconfined"],
                )
        if exposed_ports:
            create_kwargs["ports"] = {
                _docker_port_key(port): ("127.0.0.1", None) for port in exposed_ports
            }
        # ----- END VERBATIM COPY -----

        # prometheus injections — append, don't overwrite, so FUSE/SYS_ADMIN survives.
        cap_add = create_kwargs.setdefault("cap_add", [])
        if not isinstance(cap_add, list):
            cap_add = list(cap_add)
            create_kwargs["cap_add"] = cap_add
        for cap in ("NET_ADMIN", "NET_RAW"):
            if cap not in cap_add:
                cap_add.append(cap)

        extra_hosts = create_kwargs.setdefault("extra_hosts", {})
        extra_hosts["host.docker.internal"] = "host-gateway"

        # --- Tor proxy injection (OVERRIDE, not setdefault) ---
        # Route all outbound traffic through Tor SOCKS5 proxy on the host.
        # host.docker.internal resolves to the host's Docker bridge gateway.
        # ALL_PROXY covers curl, wget, and most Go/Python HTTP clients.
        #
        # session_manager.py sets proxy env vars to Caido (the in-container
        # intercepting proxy). We MUST override those with Tor — setdefault
        # silently fails when the key already exists. Use direct assignment.
        create_kwargs["environment"] = _inject_tor_proxy(
            create_kwargs.get("environment"),
        )

        logger.debug(
            "Creating sandbox container: image=%s caps=%s exposed_ports=%s",
            image,
            cap_add,
            list(exposed_ports),
        )
        try:
            container = self.docker_client.containers.create(**create_kwargs)
        except Exception as exc:
            exc_type = type(exc).__name__
            raise RuntimeError(
                f"Docker container creation failed ({exc_type}): {exc}. "
                f"Is Docker running? Try 'docker info' to check."
            ) from exc
        logger.info(
            "Sandbox container created: id=%s image=%s",
            container.short_id if hasattr(container, "short_id") else "?",
            image,
        )
        return container
