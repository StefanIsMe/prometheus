"""Top-level prometheus scan runner."""

from __future__ import annotations

import contextlib
import json
import logging
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from agents import RunConfig
from agents.sandbox import SandboxRunConfig

from prometheus.agents.factory import build_prometheus_agent, make_child_factory
from prometheus.config import load_settings
from prometheus.config.models import (
    configure_sdk_model_defaults,
    normalize_model_name,
    uses_chat_completions_tool_schema,
)
from prometheus.core.agents import AgentCoordinator
from prometheus.core.comms import set_active_run, write_status
from prometheus.tools.threat_intel.tool import clear_scan_cache
from prometheus.core.execution import (
    respawn_subagents,
    run_agent_loop,
)
from prometheus.core.execution import (
    spawn_child_agent as start_child_agent,
)
from prometheus.core.hooks import ReportUsageHooks
from prometheus.core.inputs import (
    DEFAULT_MAX_TURNS,
    build_root_task,
    build_scope_context,
    make_model_settings,
)
from prometheus.core.paths import run_dir_for, runtime_state_dir
from prometheus.core.sessions import open_agent_session
from prometheus.runtime import session_manager
from prometheus.telemetry.logging import set_scan_id, setup_scan_logging


if TYPE_CHECKING:
    from agents.memory import SQLiteSession
    from agents.result import RunResultBase


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]


async def run_prometheus_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, str]] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> RunResultBase | None:
    """Run or resume one prometheus scan against a sandbox."""
    def _progress(msg: str) -> None:
        logger.info("[scan %s] %s", scan_id, msg)
        if progress_callback:
            progress_callback(msg)

    if scan_id is None:
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    _progress("Setting up scan directories...")
    run_dir = run_dir_for(scan_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    teardown_logging = setup_scan_logging(run_dir)
    set_scan_id(scan_id)
    set_active_run(scan_id)
    clear_scan_cache()

    # --- ALWAYS warm threat intel before agents start (not lazy) ---
    from prometheus.tools.threat_intel.tool import warm_threat_intel
    _progress("Warming threat intelligence database...")
    try:
        intel_summary = await warm_threat_intel()
        logger.info("Pre-scan threat intel warmed: %s", intel_summary)
    except Exception as exc:
        _progress("Threat intel unavailable (continuing without it)")
        logger.warning("Pre-scan threat intel warm failed (non-fatal): %s", exc)
    # --- Query local threat intel DB for pre-scan context ---
    _threat_intel_context: str = ""
    try:
        from prometheus.tools.threat_intel.query_engine import query_threats
        # Build fingerprints from scan_config for local DB lookup
        _ti_fingerprints = _build_threat_fingerprints(scan_config)
        if _ti_fingerprints:
            _ti_result = await query_threats(_ti_fingerprints)
            if _ti_result.get("success") and _ti_result.get("total_vulnerabilities", 0) > 0:
                _threat_intel_context = _format_threat_intel_context(_ti_result)
                logger.info(
                    "Pre-scan threat intel: %d vulns across %d technologies (%d local, %d online)",
                    _ti_result.get("total_vulnerabilities", 0),
                    _ti_result.get("technologies_queried", 0),
                    _ti_result.get("local_hits", 0),
                    _ti_result.get("online_fallbacks", 0),
                )
    except Exception as exc:
        logger.warning("Pre-scan threat intel query failed (non-fatal): %s", exc)

    write_status(scan_id, "scan_start", {"targets": [t.get("original", "") for t in scan_config.get("targets", [])]})

    agents_path = state_dir / "agents.json"
    agents_db = state_dir / "agents.db"
    is_resume = agents_path.exists()

    logger.info(
        "%s prometheus scan %s (image=%s, max_turns=%d, interactive=%s, run_dir=%s)",
        "Resuming" if is_resume else "Starting",
        scan_id,
        image,
        max_turns,
        interactive,
        run_dir,
    )

    settings = load_settings()
    configure_sdk_model_defaults(settings)
    resolved_model = normalize_model_name(model or settings.llm.model or "")
    if not resolved_model:
        raise RuntimeError(
            "No LLM model configured. Set prometheus_LLM env or pass model= to run_prometheus_scan().",
        )
    logger.info("LLM model resolved: %s", resolved_model)
    chat_completions_tools = uses_chat_completions_tool_schema(resolved_model, settings)

    if coordinator is None:
        coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(agents_path)

    from prometheus.tools.notes.tools import hydrate_notes_from_disk
    from prometheus.tools.todo.tools import hydrate_todos_from_disk
    from prometheus.tools.knowledge.store import KnowledgeStore
    from prometheus.core.scan_goals import ScanGoalManager
    from prometheus.tools.coverage.tool import hydrate_coverage_from_disk

    hydrate_todos_from_disk(state_dir)
    hydrate_notes_from_disk(state_dir)
    hydrate_coverage_from_disk(state_dir)

    # Initialize discovery goal manager for this scan
    goal_manager = ScanGoalManager(state_dir)
    goal_manager.load()
    logger.info("Loaded %d existing discovery goals", len(goal_manager.get_all_goals()))

    # Hydrate cross-scan knowledge for target domains
    targets: list[dict[str, Any]] = scan_config.get("targets") or []
    ks = KnowledgeStore()
    prior_knowledge_summary: list[str] = []
    target_domains: list[str] = []
    for target in targets:
        domain: str = target.get("original") or target.get("value") or ""
        if domain:
            target_domains.append(domain)
            entries = ks.hydrate(domain)
            if entries:
                logger.info("Loaded %d prior knowledge entries for %s", len(entries), domain)
                # Build summary for agent injection
                for entry in entries[:20]:  # Cap at 20 to avoid context bloat
                    cat = entry.get("category", "")
                    key = entry.get("key", "")
                    val = str(entry.get("value", ""))[:200]
                    prior_knowledge_summary.append(f"  [{cat}] {key}: {val}")
                if len(entries) > 20:
                    prior_knowledge_summary.append(f"  ... and {len(entries) - 20} more entries")

            # Record scan start in target profile
            scan_mode_val = str(scan_config.get("scan_mode") or "deep")
            instruction_val = str(scan_config.get("user_instructions") or "")
            custom_headers_val = scan_config.get("custom_headers") or []
            ks.record_scan_start(
                domain=domain,
                scan_id=scan_id,
                scan_mode=scan_mode_val,
                instruction=instruction_val,
                custom_headers=custom_headers_val,
            )
            logger.info("Recorded scan start in target profile for %s", domain)

    root_id: str | None = None
    if is_resume:
        try:
            snap = json.loads(agents_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json is unreadable: {exc}",
            ) from exc
        if not agents_db.exists():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: missing SDK session database at {agents_db}",
            )
        await coordinator.restore(snap)
        for aid, parent in coordinator.parent_of.items():
            if parent is None:
                root_id = aid
                break
        if root_id is None:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json has no root agent (parent=None)",
            )
        logger.info(
            "Resume: restored coordinator with %d agent(s); root=%s",
            len(coordinator.statuses),
            root_id,
        )
    else:
        root_id = uuid.uuid4().hex[:8]

    logger.info("Bringing up sandbox session for scan %s", scan_id)
    _progress("Creating Docker sandbox (this takes 20-30s)...")
    bundle = await session_manager.create_or_reuse(
        scan_id,
        image=image,
        local_sources=local_sources or [],
    )
    _progress("Sandbox ready. Updating nuclei templates...")
    logger.info("Sandbox ready for scan %s", scan_id)

    # --- ALWAYS update nuclei templates before agents start ---
    session = bundle.get("session")
    if session:
        try:
            nuc_result = await session.exec(
                "sh", "-c",
                "which nuclei && nuclei -update-templates -silent 2>&1 || echo 'nuclei not installed'",
                timeout=60,
            )
            nuc_out = nuc_result.stdout.decode("utf-8", errors="replace").strip()[:500]
            logger.info("Pre-scan nuclei template update: %s", nuc_out)
            _progress("Nuclei templates updated. Building agents...")
        except Exception as exc:
            _progress("Nuclei update skipped (non-fatal). Building agents...")
            logger.warning("Pre-scan nuclei update failed (non-fatal): %s", exc)

    sessions_to_close: list[SQLiteSession] = []

    try:
        targets = scan_config.get("targets") or []
        scan_mode = str(scan_config.get("scan_mode") or "deep")
        is_whitebox = any(t.get("type") == "local_code" for t in targets)
        skills = list(scan_config.get("skills") or [])
        root_task = build_root_task(scan_config)

        # Inject prior knowledge into the root task if available
        if prior_knowledge_summary:
            knowledge_block = "\n".join(prior_knowledge_summary)

            # Build profile summary for rescanned targets
            profile_blocks: list[str] = []
            for domain in target_domains:
                profile = ks.get_target_profile(domain)
                if profile.get("exists"):
                    p = profile["profile"]
                    scans = profile.get("scan_history", [])
                    failed = profile.get("failed_approaches", [])
                    succeeded = profile.get("successful_techniques", [])

                    block_lines = [
                        f"\n=== TARGET PROFILE: {domain} ===",
                        f"Total scans: {p.get('scan_count', 0)}",
                        f"Total findings: {p.get('total_findings', 0)} "
                        f"(C:{p.get('critical_count',0)} H:{p.get('high_count',0)} "
                        f"M:{p.get('medium_count',0)} L:{p.get('low_count',0)} "
                        f"I:{p.get('info_count',0)})",
                        f"First scan: {p.get('first_scan_at', 'unknown')}",
                        f"Last scan: {p.get('last_scan_at', 'unknown')} ({p.get('last_status', 'unknown')})",
                    ]

                    if scans:
                        block_lines.append(f"\nScan history ({len(scans)} runs):")
                        for s in scans[:5]:  # Last 5 scans
                            block_lines.append(
                                f"  {s['scan_id']} | {s['status']} | "
                                f"{s['finding_count']} findings | "
                                f"{s.get('scan_mode', '?')} mode | "
                                f"{s.get('started_at', '?')[:10]}"
                            )

                    if failed:
                        block_lines.append("\nFailed approaches (DO NOT repeat):")
                        for f_entry in failed[:5]:
                            block_lines.append(f"  - {f_entry['key']}: {f_entry['value'][:150]}")

                    if succeeded:
                        block_lines.append("\nSuccessful techniques (build on these):")
                        for s_entry in succeeded[:5]:
                            block_lines.append(f"  - {s_entry['key']}: {s_entry['value'][:150]}")

                    block_lines.append(f"\nUse get_target_profile(\"{domain}\") for full details.")
                    block_lines.append("Use list_target_profiles() to see all scanned targets.")
                    profile_blocks.append("\n".join(block_lines))

            profile_section = "\n".join(profile_blocks) if profile_blocks else ""

            root_task = (
                f"TARGET PROFILE AND PRIOR KNOWLEDGE:\n"
                f"{profile_section}\n\n"
                f"KNOWLEDGE ENTRIES:\n{knowledge_block}\n\n"
                f"Use this knowledge to avoid repeating failed approaches and to build on "
                f"previous findings. Call get_target_profile for the full profile with scan "
                f"history. Call query_knowledge for filtered knowledge queries.\n\n"
                f"Also call save_knowledge during and after testing to persist new findings "
                f"for future scans.\n\n"
                f"{root_task}"
            )

        # Inject local threat intel context if available
        if _threat_intel_context:
            root_task = (
                f"KNOWN VULNERABILITIES (from local threat intel DB):\n"
                f"{_threat_intel_context}\n\n"
                f"Use this pre-computed vulnerability data to prioritize testing. "
                f"These CVEs were matched against detected technologies. "
                f"Focus on CISA KEV entries and high-priority CVEs first.\n\n"
                f"{root_task}"
            )

        model_settings = make_model_settings(settings.llm.reasoning_effort)
        run_config = RunConfig(
            model=resolved_model,
            model_settings=model_settings,
            sandbox=SandboxRunConfig(client=bundle["client"], session=bundle["session"]),
            trace_include_sensitive_data=False,
        )
        hooks = ReportUsageHooks(model=resolved_model)

        scope_context = build_scope_context(scan_config)

        # Use target domain as agent name for single-target scans
        agent_name = (
            (targets[0].get("original") or "prometheus").split("/")[0]
            if len(targets) == 1
            else "prometheus"
        )

        root_agent = build_prometheus_agent(
            name=agent_name,
            skills=skills,
            is_root=True,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=scope_context,
        )

        _progress("Registering root agent...")
        if not is_resume:
            await coordinator.register(
                root_id,
                agent_name,
                parent_id=None,
                task=root_task,
                skills=skills,
            )

        child_agent_builder = make_child_factory(
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=scope_context,
        )

        async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
            return await start_child_agent(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
                **kwargs,
            )

        context: dict[str, Any] = {
            "coordinator": coordinator,
            "sandbox_session": bundle["session"],
            "caido_client": bundle["caido_client"],
            "agent_id": root_id,
            "parent_id": None,
            "interactive": interactive,
            "spawn_child_agent": spawn_child_agent,
            "goal_manager": goal_manager,
            "state_dir": str(state_dir),
        }

        root_session = open_agent_session(root_id, agents_db)
        sessions_to_close.append(root_session)
        await coordinator.attach_runtime(root_id, session=root_session)

        if is_resume:
            await respawn_subagents(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                parent_ctx=context,
                root_id=root_id,
                event_sink=event_sink,
                hooks=hooks,
            )

        initial_input: Any = [] if is_resume else root_task

        _progress("Starting agent loop (first LLM call may take 10-20s)...")
        # Resume + new ``--instruction``: SDK replay drives root from
        # agents.db with ``initial_input=[]``, so a brand-new instruction
        # passed on the resume CLI would otherwise be silently ignored.
        # Inject it as a fresh user message in root's SDK session; the
        # next run cycle will replay it with the rest of the session.
        resume_instruction = str(scan_config.get("resume_instruction") or "").strip()
        if is_resume and resume_instruction:
            await coordinator.send(
                root_id,
                {
                    "from": "user",
                    "type": "instruction",
                    "priority": "high",
                    "content": resume_instruction,
                },
            )
            logger.info(
                "Resume: injected new instruction into root SDK session (len=%d)",
                len(resume_instruction),
            )

        async with coordinator._lock:
            root_status = coordinator.statuses.get(root_id)

        return await run_agent_loop(
            agent=root_agent,
            initial_input=initial_input,
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            coordinator=coordinator,
            agent_id=root_id,
            interactive=interactive,
            session=root_session,
            start_parked=bool(interactive and is_resume and root_status != "running"),
            event_sink=event_sink,
            hooks=hooks,
        )
    except BaseException:
        logger.exception("prometheus scan %s failed", scan_id)
        if root_id is not None:
            await coordinator.cancel_descendants(root_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "failed")
        raise
    finally:
        for s in sessions_to_close:
            with contextlib.suppress(Exception):
                s.close()
        with contextlib.suppress(Exception):
            await coordinator._maybe_snapshot()
        if cleanup_on_exit:
            logger.info("Tearing down sandbox session for scan %s", scan_id)
            await session_manager.cleanup(scan_id)

        # Record scan end in target profiles
        try:
            vuln_path = run_dir / "vulnerabilities.json"
            findings_list: list[dict[str, Any]] = []
            if vuln_path.exists():
                findings_list = json.loads(vuln_path.read_text(encoding="utf-8"))
            # Determine final status
            scan_status = "completed"
            try:
                run_json_path = run_dir / "run.json"
                if run_json_path.exists():
                    run_data = json.loads(run_json_path.read_text(encoding="utf-8"))
                    scan_status = run_data.get("status", "completed")
                    llm_usage = run_data.get("llm_usage", {})
                    llm_requests = llm_usage.get("requests")
                    total_tokens = llm_usage.get("total_tokens")
                else:
                    llm_requests = None
                    total_tokens = None
            except Exception:
                llm_requests = None
                total_tokens = None

            for domain in target_domains:
                ks.record_scan_end(
                    domain=domain,
                    scan_id=scan_id,
                    status=scan_status,
                    findings=findings_list,
                    llm_requests=llm_requests,
                    total_tokens=total_tokens,
                )
                # Auto-register findings in report_status tracker
                if findings_list:
                    try:
                        sync_result = ks.sync_scan_findings(
                            domain=domain,
                            scan_id=scan_id,
                            findings=findings_list,
                        )
                        logger.info(
                            "Synced %d new findings to report_status for %s",
                            sync_result.get("created", 0), domain,
                        )
                    except Exception:
                        logger.exception("Failed to sync findings to report_status for %s", domain)
                logger.info(
                    "Recorded scan end in target profile for %s: %d findings, status=%s",
                    domain, len(findings_list), scan_status,
                )
        except Exception:
            logger.exception("Failed to record scan end in target profiles")

        logger.info("prometheus scan %s done", scan_id)
        write_status(scan_id, "scan_complete", {"status": "completed"})
        teardown_logging()


# ---------------------------------------------------------------------------
# Threat intel helpers (used by the pre-scan injection above)
# ---------------------------------------------------------------------------

def _build_threat_fingerprints(scan_config: dict[str, Any]) -> list[dict[str, str]]:
    """Extract technology fingerprints from scan_config for threat intel lookup.
    Looks at targets for hints about the technology stack being scanned.
    """
    fingerprints: list[dict[str, str]] = []
    seen: set[str] = set()

    # Extract from targets — look for technology hints in URL patterns
    targets = scan_config.get("targets") or []
    for target in targets:
        original = target.get("original") or target.get("value") or ""
        if not original:
            continue

        # Check for tech hints in scan_config
        tech_hints = scan_config.get("tech_stack") or []
        for hint in tech_hints:
            tech = hint.get("technology", "").strip()
            version = hint.get("version", "").strip()
            key = f"{tech}@{version}".lower()
            if tech and key not in seen:
                seen.add(key)
                fingerprints.append({"technology": tech, "version": version})

    return fingerprints


def _format_threat_intel_context(result: dict[str, Any]) -> str:
    """Format threat intel query results for injection into agent context."""
    lines: list[str] = []
    lines.append(f"Total: {result.get('total_vulnerabilities', 0)} vulnerabilities "
                 f"across {result.get('technologies_queried', 0)} technologies")
    if result.get("cisa_kev_matches_total"):
        lines.append(f"CISA KEV matches: {result['cisa_kev_matches_total']}")
    lines.append("")

    for tech_result in result.get("results", []):
        tech = tech_result.get("technology", "?")
        version = tech_result.get("version", "?")
        vulns = tech_result.get("vulnerabilities", [])
        if not vulns:
            continue

        lines.append(f"=== {tech} {version} ({len(vulns)} CVEs) ===")
        for v in vulns[:15]:  # Cap per-tech to avoid context bloat
            cve_id = v.get("cve_id", "?")
            severity = v.get("severity", "?")
            cvss = v.get("cvss_score", 0)
            score = v.get("priority_score", 0)
            kev = " [CISA-KEV]" if v.get("cisa_kev") or v.get("in_cisa_kev") else ""
            exploit = " [EXPLOIT]" if v.get("has_exploit") else ""
            desc = (v.get("description") or "")[:80]
            lines.append(
                f"  [{severity} CVSS:{cvss} Score:{score}] {cve_id}"
                f"{kev}{exploit} — {desc}"
            )
        if len(vulns) > 15:
            lines.append(f"  ... and {len(vulns) - 15} more")
        lines.append("")

    return "\n".join(lines)
