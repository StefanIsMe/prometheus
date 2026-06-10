"""Tests for attack surface graph and workflow mutation helpers."""

from __future__ import annotations

from prometheus.core.attack_surface import AttackSurfaceGraph, WorkflowMutationPlanner


def test_attack_surface_graph_persists_nodes_edges_and_surface_signature(tmp_path):
    graph = AttackSurfaceGraph(tmp_path)

    endpoint_id = graph.add_node(
        node_type="endpoint",
        key="GET /api/orders/{order_id}",
        attrs={"path": "/api/orders/123", "method": "GET"},
    )
    param_id = graph.add_node(
        node_type="parameter",
        key="order_id",
        attrs={"location": "path", "sample": "123"},
    )
    graph.add_edge(endpoint_id, param_id, relation="uses_parameter", evidence="path template")

    summary = graph.summary()
    assert summary["nodes"] == 2
    assert summary["edges"] == 1
    assert summary["by_type"]["endpoint"] == 1
    assert len(graph.surface_signature()) == 16

    reloaded = AttackSurfaceGraph(tmp_path)
    reloaded.load()
    assert reloaded.summary()["nodes"] == 2
    assert reloaded.summary()["edges"] == 1


def test_workflow_mutation_planner_generates_agnostic_security_mutations():
    planner = WorkflowMutationPlanner()

    mutations = planner.suggest_mutations(
        endpoint="/api/orders/123",
        method="GET",
        parameters=["order_id", "user_id"],
        auth_state="authenticated",
        content_type="application/json",
        workflow_step="resource read",
    )

    mutation_names = {m["name"] for m in mutations}
    assert "remove_authorization_header" in mutation_names
    assert "swap_object_identifier" in mutation_names
    assert "duplicate_parameter" in mutation_names
    assert "json_to_form_content_type" in mutation_names
    assert "replay_as_logged_out" in mutation_names
