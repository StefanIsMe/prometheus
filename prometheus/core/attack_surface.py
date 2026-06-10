"""Attack surface graph and agnostic workflow mutation planning."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class SurfaceNode:
    """One attack surface node."""

    id: str
    node_type: str
    key: str
    attrs: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass(slots=True)
class SurfaceEdge:
    """One typed relationship between attack surface nodes."""

    id: str
    source_id: str
    target_id: str
    relation: str
    evidence: str = ""
    created_at: float = field(default_factory=time.time)


def _node_id(node_type: str, key: str) -> str:
    digest = hashlib.sha256(f"{node_type}:{key}".encode()).hexdigest()[:12]
    return f"surf_{digest}"


def _edge_id(source_id: str, target_id: str, relation: str) -> str:
    digest = hashlib.sha256(f"{source_id}:{target_id}:{relation}".encode()).hexdigest()[:12]
    return f"edge_{digest}"


class AttackSurfaceGraph:
    """Persistent graph of target hosts, paths, inputs, roles, and workflows."""

    def __init__(self, state_dir: Path | str) -> None:
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / "attack_surface.json"
        self.nodes: dict[str, SurfaceNode] = {}
        self.edges: dict[str, SurfaceEdge] = {}
        self.load()

    def add_node(
        self,
        *,
        node_type: str,
        key: str,
        attrs: dict[str, Any] | None = None,
    ) -> str:
        node_id = _node_id(node_type, key)
        now = time.time()
        existing = self.nodes.get(node_id)
        if existing:
            existing.attrs.update(attrs or {})
            existing.updated_at = now
        else:
            self.nodes[node_id] = SurfaceNode(
                id=node_id,
                node_type=node_type,
                key=key,
                attrs=attrs or {},
                created_at=now,
                updated_at=now,
            )
        self.persist()
        return node_id

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        *,
        relation: str,
        evidence: str = "",
    ) -> str:
        if source_id not in self.nodes:
            raise KeyError(f"Unknown attack surface source node: {source_id}")
        if target_id not in self.nodes:
            raise KeyError(f"Unknown attack surface target node: {target_id}")
        edge_id = _edge_id(source_id, target_id, relation)
        self.edges[edge_id] = SurfaceEdge(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            evidence=evidence,
        )
        self.persist()
        return edge_id

    def summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        by_relation: dict[str, int] = {}
        for node in self.nodes.values():
            by_type[node.node_type] = by_type.get(node.node_type, 0) + 1
        for edge in self.edges.values():
            by_relation[edge.relation] = by_relation.get(edge.relation, 0) + 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "by_type": by_type,
            "by_relation": by_relation,
            "surface_signature": self.surface_signature(),
        }

    def surface_signature(self) -> str:
        payload = {
            "nodes": sorted(
                (node.node_type, node.key, sorted(node.attrs.items()))
                for node in self.nodes.values()
            ),
            "edges": sorted(
                (edge.source_id, edge.target_id, edge.relation) for edge in self.edges.values()
            ),
        }
        encoded = json.dumps(payload, sort_keys=True, default=str).encode()
        return hashlib.sha256(encoded).hexdigest()[:16]

    def load(self) -> None:
        if not self.path.exists():
            self.nodes = {}
            self.edges = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.nodes = {}
            self.edges = {}
            return
        self.nodes = {}
        self.edges = {}
        for item in raw.get("nodes", []):
            if isinstance(item, dict):
                fallback_id = _node_id(str(item.get("node_type")), str(item.get("key")))
                node = SurfaceNode(
                    id=str(item.get("id") or fallback_id),
                    node_type=str(item.get("node_type") or "unknown"),
                    key=str(item.get("key") or ""),
                    attrs=item.get("attrs") if isinstance(item.get("attrs"), dict) else {},
                    created_at=float(item.get("created_at") or time.time()),
                    updated_at=float(item.get("updated_at") or time.time()),
                )
                self.nodes[node.id] = node
        for item in raw.get("edges", []):
            if isinstance(item, dict):
                edge = SurfaceEdge(
                    id=str(
                        item.get("id")
                        or _edge_id(
                            str(item.get("source_id")),
                            str(item.get("target_id")),
                            str(item.get("relation")),
                        ),
                    ),
                    source_id=str(item.get("source_id") or ""),
                    target_id=str(item.get("target_id") or ""),
                    relation=str(item.get("relation") or "related"),
                    evidence=str(item.get("evidence") or ""),
                    created_at=float(item.get("created_at") or time.time()),
                )
                self.edges[edge.id] = edge

    def persist(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "nodes": [asdict(node) for node in self.nodes.values()],
            "edges": [asdict(edge) for edge in self.edges.values()],
        }
        data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(self.state_dir),
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        tmp_path.replace(self.path)


class WorkflowMutationPlanner:
    """Generate target agnostic workflow mutations for novel bug discovery."""

    def suggest_mutations(
        self,
        *,
        endpoint: str,
        method: str,
        parameters: list[str] | None = None,
        auth_state: str = "",
        content_type: str = "",
        workflow_step: str = "",
    ) -> list[dict[str, Any]]:
        params = parameters or []
        mutations: list[dict[str, Any]] = []

        if auth_state:
            mutations.append(
                self._mutation(
                    "remove_authorization_header",
                    "Replay the request without Authorization and session cookies.",
                    endpoint,
                    method,
                    workflow_step,
                ),
            )
            mutations.append(
                self._mutation(
                    "replay_as_logged_out",
                    "Replay the workflow from a clean logged out browser context.",
                    endpoint,
                    method,
                    workflow_step,
                ),
            )
            mutations.append(
                self._mutation(
                    "swap_session_role",
                    "Replay the same request with a lower privilege account and compare responses.",
                    endpoint,
                    method,
                    workflow_step,
                ),
            )

        identifier_tokens = ["id", "uuid", "user", "order", "account"]
        identifier_params = [
            p for p in params if any(token in p.lower() for token in identifier_tokens)
        ]
        if identifier_params:
            mutations.append(
                self._mutation(
                    "swap_object_identifier",
                    "Replace object identifiers with values from another controlled account.",
                    endpoint,
                    method,
                    workflow_step,
                    {"parameters": identifier_params},
                ),
            )

        if params:
            mutations.append(
                self._mutation(
                    "duplicate_parameter",
                    "Send the same parameter twice with conflicting values.",
                    endpoint,
                    method,
                    workflow_step,
                    {"parameters": params},
                ),
            )
            mutations.append(
                self._mutation(
                    "move_parameter_location",
                    "Move parameters between query string, body, cookie, and header.",
                    endpoint,
                    method,
                    workflow_step,
                    {"parameters": params},
                ),
            )

        if "json" in content_type.lower():
            mutations.append(
                self._mutation(
                    "json_to_form_content_type",
                    "Replay JSON request as form-encoded and multipart/form-data.",
                    endpoint,
                    method,
                    workflow_step,
                ),
            )
        elif "form" in content_type.lower():
            mutations.append(
                self._mutation(
                    "form_to_json_content_type",
                    "Replay form request as JSON with equivalent fields.",
                    endpoint,
                    method,
                    workflow_step,
                ),
            )

        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            mutations.append(
                self._mutation(
                    "race_state_changing_request",
                    "Send concurrent state-changing requests and compare side effects.",
                    endpoint,
                    method,
                    workflow_step,
                ),
            )
            mutations.append(
                self._mutation(
                    "method_override",
                    "Replay with X-HTTP-Method-Override and _method variants.",
                    endpoint,
                    method,
                    workflow_step,
                ),
            )

        if any(token in endpoint.lower() for token in ["redirect", "callback", "return", "url"]):
            mutations.append(
                self._mutation(
                    "redirect_chain_to_internal",
                    "Replace redirect targets with controlled, localhost, and metadata URLs.",
                    endpoint,
                    method,
                    workflow_step,
                ),
            )

        if not mutations:
            mutations.append(
                self._mutation(
                    "baseline_differential_probe",
                    "Replay benign value changes and compare response fingerprints.",
                    endpoint,
                    method,
                    workflow_step,
                ),
            )
        return mutations

    @staticmethod
    def _mutation(
        name: str,
        description: str,
        endpoint: str,
        method: str,
        workflow_step: str,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "id": f"mut_{uuid.uuid4().hex[:8]}",
            "name": name,
            "description": description,
            "endpoint": endpoint,
            "method": method.upper(),
            "workflow_step": workflow_step,
        }
        if extra:
            payload.update(extra)
        return payload


_active_graph: AttackSurfaceGraph | None = None


def hydrate_attack_surface_from_disk(state_dir: Path | str) -> None:
    """Initialize the active attack surface graph."""

    global _active_graph  # noqa: PLW0603
    _active_graph = AttackSurfaceGraph(state_dir)


def get_active_attack_surface_graph() -> AttackSurfaceGraph | None:
    """Return the active attack surface graph if hydrated."""

    return _active_graph


def require_active_attack_surface_graph() -> AttackSurfaceGraph:
    """Return the active graph or raise a clear runtime error."""

    if _active_graph is None:
        raise RuntimeError(
            "AttackSurfaceGraph not initialised — call hydrate_attack_surface_from_disk first",
        )
    return _active_graph
