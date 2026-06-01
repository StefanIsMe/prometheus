"""Execution loop for addressable SDK-backed prometheus agents."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

import httpx

from agents import RunConfig, Runner
from agents.exceptions import AgentsException, MaxTurnsExceeded, UserError
from agents.stream_events import RunItemStreamEvent
from openai import APIConnectionError, APIError

from prometheus.core.inputs import child_initial_input
from prometheus.core.comms import get_active_run, write_status
from prometheus.core.sessions import open_agent_session, strip_latest_image_from_session


if TYPE_CHECKING:
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.lifecycle import RunHooks
    from agents.memory import Session, SQLiteSession
    from agents.result import RunResultBase

    from prometheus.core.agents import AgentCoordinator, Status


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]

_INPUT_REJECTION_CODES = frozenset({400, 404, 422})

# Context cap: ~50K tokens, assuming 4 chars per token
_CHARS_PER_TOKEN = 4
_MAX_TASK_CHARS = 50_000 * _CHARS_PER_TOKEN

# --- Fix 1: stagger child-agent spawns so they don't all hit the API ---
# at the same instant.  The lock serialises spawns; the sleep gives each
# child a head-start before the next one begins its first API call.
_spawn_lock = asyncio.Lock()
_CHILD_SPAWN_STAGGER_SECONDS = 3.0

# --- Fix 3: retry child-agent runs on provider (API) errors ---
_provider_error_retries: dict[str, int] = {}
_PROVIDER_ERROR_MAX_RETRIES = 3
_PROVIDER_ERROR_BASE_DELAY = 5.0  # seconds; backs off 5 → 10 → 20

# --- Fix 4: retry on transport errors (mid-stream connection drops) ---
_TRANSPORT_ERROR_TYPES = (
    httpx.RemoteProtocolError,
    httpx.ReadError,
    httpx.ConnectError,
    APIConnectionError,
    TimeoutError,  # Fix 5: stream stall watchdog (asyncio.timeout)
)
_TRANSPORT_ERROR_MAX_RETRIES = 3
_TRANSPORT_ERROR_BASE_DELAY = 5.0  # seconds; backs off 5 → 10 → 20
_transport_error_retries: dict[str, int] = {}

# --- Fix 5: stream stall watchdog ---
# If no stream event arrives within this many seconds, the LLM connection is
# considered dead (CLOSE-WAIT / half-open).  The timeout resets on every event.
_STREAM_STALL_TIMEOUT = 300  # 5 minutes

# --- Circuit breaker: cap child-agent turns to prevent runaway token spend ---
_MAX_CHILD_TURNS = 999999  # effectively unlimited — Stefan wants no turn cap
_MAX_CONSECUTIVE_ERRORS = 10  # max consecutive same-tool errors before forced stop

# Per-child-agent consecutive error tracking: agent_id -> (tool_name, count)
_consecutive_tool_errors: dict[str, tuple[str, int]] = {}


async def run_agent_loop(
    *,
    agent: Any,
    initial_input: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    coordinator: AgentCoordinator,
    agent_id: str,
    interactive: bool,
    session: Session | None = None,
    start_parked: bool = False,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> RunResultBase | None:
    await coordinator.attach_runtime(
        agent_id,
        session=session,
        interrupt_on_message=interactive,
    )
    result: RunResultBase | None = None

    if not (start_parked and interactive):
        if interactive:
            result = await _run_cycle(
                agent,
                coordinator,
                agent_id,
                input_data=initial_input,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
            )
        else:
            result = await _run_noninteractive_until_lifecycle(
                agent,
                coordinator,
                agent_id,
                initial_input=initial_input,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                event_sink=event_sink,
                hooks=hooks,
            )

    if not interactive:
        return result

    while True:
        try:
            await coordinator.wait_for_message(agent_id)
        except asyncio.CancelledError:
            return result

        await coordinator.consume_pending(agent_id)
        result = await _run_cycle(
            agent,
            coordinator,
            agent_id,
            input_data=[],
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            session=session,
            interactive=interactive,
            event_sink=event_sink,
            hooks=hooks,
        )


async def spawn_child_agent(
    *,
    coordinator: AgentCoordinator,
    factory: Any,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    parent_ctx: dict[str, Any],
    name: str,
    task: str,
    skills: list[str],
    parent_history: list[Any] | None = None,  # deprecated; ignored
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if len(task) > _MAX_TASK_CHARS:
        logger.warning(
            "spawn_child_agent: truncating task for '%s' from %d to %d chars (~%d tokens)",
            name,
            len(task),
            _MAX_TASK_CHARS,
            _MAX_TASK_CHARS // _CHARS_PER_TOKEN,
        )
        task = task[:_MAX_TASK_CHARS] + "\n\n[Task description truncated to fit context window]"

    parent_id = parent_ctx.get("agent_id")
    if not isinstance(parent_id, str):
        raise TypeError("Parent agent_id missing from context")

    child_id = uuid.uuid4().hex[:8]
    child_agent = factory(name=name, skills=skills)
    await coordinator.register(
        child_id,
        name,
        parent_id,
        task=task,
        skills=skills,
    )

    # Fix 1: stagger child spawns so concurrent create_agent calls don't
    # all fire their first API request at the same instant.
    async with _spawn_lock:
        await asyncio.sleep(_CHILD_SPAWN_STAGGER_SECONDS)
        await _start_child_runner(
            parent_ctx=parent_ctx,
            coordinator=coordinator,
            agents_db_path=agents_db_path,
            sessions_to_close=sessions_to_close,
            run_config=run_config,
            max_turns=max_turns,
            interactive=interactive,
            child_agent=child_agent,
            child_id=child_id,
            name=name,
            parent_id=parent_id,
            task=task,
            initial_input=child_initial_input(
                name=name,
                child_id=child_id,
                parent_id=parent_id,
                task=task,
            ),
            event_sink=event_sink,
            hooks=hooks,
        )

    return {
        "success": True,
        "agent_id": child_id,
        "name": name,
        "parent_id": parent_id,
        "message": f"Spawned '{name}' ({child_id}) running in parallel.",
    }


async def respawn_subagents(
    *,
    coordinator: AgentCoordinator,
    factory: Any,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    parent_ctx: dict[str, Any],
    root_id: str,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> None:
    async with coordinator._lock:
        agents_snapshot = [
            (aid, status, dict(coordinator.metadata.get(aid, {})))
            for aid, status in coordinator.statuses.items()
        ]
        candidates: list[tuple[str, str, str | None, dict[str, Any]]] = []
        for aid, status, md in agents_snapshot:
            if not interactive and status not in {"running", "waiting"}:
                continue
            if coordinator.parent_of.get(aid) is None or aid == root_id:
                continue
            md["_restored_status"] = status
            candidates.append(
                (
                    aid,
                    coordinator.names.get(aid, aid),
                    coordinator.parent_of.get(aid),
                    md,
                )
            )

    for child_id, name, parent_id, md in candidates:
        try:
            restored_status = str(md.get("_restored_status") or "running")
            start_parked = interactive and restored_status != "running"

            if start_parked:
                logger.warning(
                    "respawn %s (%s): starting parked from status=%s",
                    child_id,
                    name,
                    restored_status,
                )

            child_skills = list(md.get("skills") or [])
            child_agent = factory(name=name, skills=child_skills)
            await _start_child_runner(
                parent_ctx=parent_ctx,
                coordinator=coordinator,
                agents_db_path=agents_db_path,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                child_agent=child_agent,
                child_id=child_id,
                name=name,
                parent_id=parent_id,
                task=str(md.get("task", "")),
                initial_input=[],
                start_parked=start_parked,
                event_sink=event_sink,
                hooks=hooks,
            )
            logger.info(
                "respawned %s (%s) parent=%s task_len=%d",
                child_id,
                name,
                parent_id or "-",
                len(md.get("task", "")),
            )
        except Exception:
            logger.exception("respawn %s failed; marking crashed", child_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(child_id, "crashed")


def _maybe_create_goal_from_result(
    result: RunResultBase | None,
    goal_manager: Any,
) -> None:
    """Check if the agent just filed a finding; if so, create a discovery goal."""
    if result is None:
        return

    # Look for create_vulnerability_report tool calls in the result
    new_items = getattr(result, "new_items", None)
    if not new_items:
        return

    from prometheus.core.scan_goals import classify_finding_type

    for item in new_items:
        # Check for function call outputs from create_vulnerability_report
        item_type = getattr(item, "type", "")
        if item_type != "function_call_output":
            continue

        tool_call_id = getattr(item, "tool_call_id", "")
        output = getattr(item, "output", "")

        # Check if this is from create_vulnerability_report
        if not isinstance(output, str):
            continue

        # Look for successful finding creation (the tool returns JSON with success=True and a title)
        try:
            import json as _json
            data = _json.loads(output) if output.startswith("{") else {}
        except (ValueError, TypeError):
            continue

        if not data.get("success") or not data.get("title"):
            continue

        # Check if we already have a goal for this finding
        title = data["title"]
        endpoint = data.get("endpoint", "")
        existing = goal_manager.get_active_goal()
        if existing and existing.finding_title == title:
            continue  # already tracking this

        # Create a discovery goal
        finding_type = classify_finding_type(title, data.get("description", ""))
        goal = goal_manager.create_goal({
            "title": title,
            "description": data.get("description", ""),
            "endpoint": endpoint,
            "finding_type": finding_type,
        })
        logger.info(
            "Created discovery goal for finding: %s (type=%s, endpoint=%s)",
            title, finding_type, endpoint,
        )
        goal_manager.persist()


async def _run_noninteractive_until_lifecycle(
    agent: Any,
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    initial_input: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    session: Session | None,
    event_sink: StreamEventSink | None,
    hooks: RunHooks[dict[str, Any]] | None,
) -> RunResultBase | None:
    """Non-chat mode keeps running until finish_scan / agent_finish settles status."""
    result: RunResultBase | None = None
    input_data: Any = initial_input
    invalid_final_outputs = 0
    invalid_final_output_limit = max(1, max_turns)

    run_id = get_active_run()
    turn_counter = 0
    while True:
        turn_counter += 1
        if run_id:
            write_status(run_id, "turn_start", {"turn": turn_counter, "agent_id": agent_id})
        result = await _run_cycle(
            agent,
            coordinator,
            agent_id,
            input_data=input_data,
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            session=session,
            interactive=False,
            event_sink=event_sink,
            hooks=hooks,
        )

        # --- DISCOVERY GOAL EVALUATION (root agent only) ---
        goal_manager = context.get("goal_manager")
        if goal_manager and context.get("parent_id") is None:
            try:
                from prometheus.core.scan_goals import judge_scan_goal, generate_continuation_prompt

                # Check if a finding was just filed — create goal if so
                _maybe_create_goal_from_result(result, goal_manager)

                active_goal = goal_manager.get_active_goal()
                if active_goal:
                    last_output = _final_output_preview(result)
                    verdict = judge_scan_goal(active_goal, last_output)
                    if verdict.get("done"):
                        poc_status = verdict.get("poc_status", "working")
                        reason = verdict.get("reason", "")
                        goal_manager.complete_goal(
                            active_goal.id,
                            status="validated" if poc_status == "working" else "dead_end",
                            poc_status=poc_status,
                            dead_end_reason="" if poc_status == "working" else reason,
                        )
                        goal_manager.persist()
                        logger.info(
                            "Discovery goal completed: %s (status=%s, poc=%s)",
                            active_goal.finding_title,
                            "validated" if poc_status == "working" else "dead_end",
                            poc_status,
                        )
                    else:
                        # Goal not done — inject continuation prompt
                        continuation = generate_continuation_prompt(active_goal)
                        active_goal.attempts += 1
                        if active_goal.attempts in active_goal.continuation_history:
                            pass  # avoid duplicates
                        else:
                            active_goal.continuation_history.append(continuation[:200])
                        goal_manager.persist()
                        logger.info(
                            "Discovery goal not done (attempt %d/%d): %s — injecting continuation",
                            active_goal.attempts,
                            active_goal.max_attempts,
                            active_goal.finding_title,
                        )
                        input_data = continuation
                        if active_goal.attempts >= active_goal.max_attempts:
                            goal_manager.complete_goal(
                                active_goal.id,
                                status="abandoned",
                                dead_end_reason=f"Max attempts ({active_goal.max_attempts}) reached",
                            )
                            goal_manager.persist()
                            logger.warning("Discovery goal abandoned: %s", active_goal.finding_title)
                        continue  # skip the invalid_final_outputs counter
            except Exception as exc:
                logger.warning("Goal evaluation failed (non-fatal): %s", exc)

        status = await _agent_status(coordinator, agent_id)
        if status != "running":
            return result

        invalid_final_outputs += 1
        logger.warning(
            "agent %s produced non-lifecycle final output in non-interactive mode; "
            "forcing tool continuation (%d/%d): %s",
            agent_id,
            invalid_final_outputs,
            invalid_final_output_limit,
            _final_output_preview(result),
        )

        if invalid_final_outputs >= invalid_final_output_limit:
            await coordinator.set_status(agent_id, "crashed")
            await _notify_parent_on_terminal(coordinator, agent_id, "crashed")
            raise MaxTurnsExceeded(
                "Agent exhausted non-interactive recovery attempts without calling "
                "finish_scan or agent_finish."
            )

        input_data = await _append_noninteractive_tool_required_message(
            session=session,
            context=context,
            attempt=invalid_final_outputs,
            limit=invalid_final_output_limit,
        )


class ChildAgentCircuitBreakerError(AgentsException):
    """Raised when a child agent hits the consecutive-same-tool-error limit."""


def _check_consecutive_tool_errors(
    agent_id: str,
    event: RunItemStreamEvent,
) -> None:
    """Track consecutive calls to the same tool; raise if the limit is hit.

    This catches runaway retry loops where the LLM keeps calling the same
    failing tool (e.g. nuclei) without making progress.
    """
    if event.name == "tool_called":
        new_tool = _extract_tool_name(event)
        prev_tool, count = _consecutive_tool_errors.get(agent_id, ("", 0))
        # Preserve count if same tool; reset if different tool
        _consecutive_tool_errors[agent_id] = (new_tool, count if new_tool == prev_tool else 0)

    elif event.name == "tool_output":
        tool_name, count = _consecutive_tool_errors.get(agent_id, ("", 0))
        if not tool_name:
            return
        output = getattr(event.item, "output", "")
        is_error = isinstance(output, str) and "error" in output.lower()
        if is_error:
            count += 1
            _consecutive_tool_errors[agent_id] = (tool_name, count)
            if count >= _MAX_CONSECUTIVE_ERRORS:
                _consecutive_tool_errors.pop(agent_id, None)
                raise ChildAgentCircuitBreakerError(
                    f"Tool '{tool_name}' failed {count} consecutive times — "
                    "stopping to prevent token waste"
                )
        else:
            # Reset on success
            _consecutive_tool_errors[agent_id] = (tool_name, 0)


def _extract_tool_name(event: RunItemStreamEvent) -> str:
    """Best-effort extraction of tool name from a tool_called event."""
    item = event.item
    raw = getattr(item, "raw_item", None)
    if isinstance(raw, dict):
        return raw.get("name", "") or raw.get("call_id", "unknown")
    # ResponseFunctionToolCall, McpCall, etc. have a .name attribute
    name = getattr(raw, "name", None)
    if name:
        return str(name)
    return "unknown"


async def _run_cycle(  # noqa: PLR0912
    agent: Any,
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    input_data: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    session: Session | None,
    interactive: bool,
    event_sink: StreamEventSink | None,
    hooks: RunHooks[dict[str, Any]] | None,
) -> RunResultBase | None:
    image_strips = 0
    stream = None
    while True:
        try:
            await coordinator.mark_running(agent_id)
            _cycle_start = time.monotonic()
            logger.info(
                "[agent %s] Starting run_streamed (input_len=%d, max_turns=%d)",
                agent_id, len(str(input_data)), max_turns,
            )
            stream = Runner.run_streamed(
                agent,
                input=input_data,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                hooks=hooks,
            )
            logger.info("[agent %s] run_streamed returned, attaching stream", agent_id)
            await coordinator.attach_stream(agent_id, stream)
            try:
                _first_event = True
                loop = asyncio.get_event_loop()
                # Fix 5: wrap stream_events with a per-event stall timeout.
                # If no event arrives within _STREAM_STALL_TIMEOUT seconds the
                # LLM connection is dead (CLOSE-WAIT).  reschedule() resets
                # the deadline on every event so busy scans never time out.
                async with asyncio.timeout(_STREAM_STALL_TIMEOUT) as _stall:
                    async for event in stream.stream_events():
                        _stall.reschedule(loop.time() + _STREAM_STALL_TIMEOUT)
                        if _first_event:
                            _first_event = False
                            _elapsed = time.monotonic() - _cycle_start
                            logger.info(
                                "[agent %s] First stream event after %.1fs",
                                agent_id, _elapsed,
                            )
                        # --- Circuit breaker: track consecutive same-tool errors ---
                        if (
                            context.get("parent_id") is not None
                            and isinstance(event, RunItemStreamEvent)
                        ):
                            _check_consecutive_tool_errors(agent_id, event)
                        if event_sink is not None:
                            try:
                                event_sink(agent_id, event)
                            except Exception:
                                logger.exception("stream event sink failed for %s", agent_id)
                if stream.run_loop_exception is not None:
                    raise stream.run_loop_exception
            finally:
                await coordinator.detach_stream(agent_id, stream)
        except Exception as exc:
            if (
                image_strips < 3
                and session is not None
                and getattr(exc, "status_code", None) in _INPUT_REJECTION_CODES
            ):
                try:
                    stripped = await strip_latest_image_from_session(session)
                except Exception:
                    logger.exception("image-strip recovery failed for %s", agent_id)
                    stripped = False
                if stripped:
                    image_strips += 1
                    logger.info(
                        "Stripped latest image from %s session after rejection; retrying (%d)",
                        agent_id,
                        image_strips,
                    )
                    input_data = []
                    continue
            # Fix 4: retry on transport errors (mid-stream connection drops)
            # Works for ALL agents (root + child) since these are transient network issues.
            if isinstance(exc, _TRANSPORT_ERROR_TYPES):
                # Fix 5: cancel the stream on stall timeout to kill the stuck
                # background LLM task (prevents task/connection leaks).
                if isinstance(exc, TimeoutError) and stream is not None:
                    try:
                        stream.cancel()
                    except Exception:
                        logger.debug("[agent %s] stream.cancel() after stall failed", agent_id, exc_info=True)
                retries = _transport_error_retries.get(agent_id, 0)
                if retries < _TRANSPORT_ERROR_MAX_RETRIES:
                    _transport_error_retries[agent_id] = retries + 1
                    delay = _TRANSPORT_ERROR_BASE_DELAY * (2 ** retries)
                    logger.warning(
                        "Transport error for %s; retry %d/%d after %.1fs: %s",
                        agent_id,
                        retries + 1,
                        _TRANSPORT_ERROR_MAX_RETRIES,
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
                    continue
                # retries exhausted — clean up and fall through
                _transport_error_retries.pop(agent_id, None)
            if not interactive:
                # Fix 3: for child agents, retry on provider (API) errors
                # before propagating the exception.
                if isinstance(exc, APIError) and context.get("parent_id") is not None:
                    retries = _provider_error_retries.get(agent_id, 0)
                    if retries < _PROVIDER_ERROR_MAX_RETRIES:
                        _provider_error_retries[agent_id] = retries + 1
                        delay = _PROVIDER_ERROR_BASE_DELAY * (2 ** retries)
                        logger.warning(
                            "Provider error for child %s; retry %d/%d after %.1fs: %s",
                            agent_id,
                            retries + 1,
                            _PROVIDER_ERROR_MAX_RETRIES,
                            delay,
                            exc,
                        )
                        await asyncio.sleep(delay)
                        continue
                    # retries exhausted — clean up and fall through
                    _provider_error_retries.pop(agent_id, None)
                if isinstance(exc, MaxTurnsExceeded | ChildAgentCircuitBreakerError):
                    status = "stopped"
                    logger.info("Child agent %s stopped: %s", agent_id, type(exc).__name__)
                    if coordinator:
                        await coordinator.set_status(agent_id, status)
                    _consecutive_tool_errors.pop(agent_id, None)
                    await _notify_parent_on_terminal(coordinator, agent_id, status)
                    return None
                raise
            # Fix 3: for interactive child agents, retry on provider errors
            # before parking as failed.
            if isinstance(exc, APIError) and context.get("parent_id") is not None:
                retries = _provider_error_retries.get(agent_id, 0)
                if retries < _PROVIDER_ERROR_MAX_RETRIES:
                    _provider_error_retries[agent_id] = retries + 1
                    delay = _PROVIDER_ERROR_BASE_DELAY * (2 ** retries)
                    logger.warning(
                        "Provider error for child %s; retry %d/%d after %.1fs: %s",
                        agent_id,
                        retries + 1,
                        _PROVIDER_ERROR_MAX_RETRIES,
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
                    continue
                # retries exhausted — clean up and fall through
                _provider_error_retries.pop(agent_id, None)
            if isinstance(exc, MaxTurnsExceeded | ChildAgentCircuitBreakerError):
                status: Status = "stopped"
            elif isinstance(exc, UserError | AgentsException | APIError):
                status = "failed"
            else:
                status = "crashed"
            logger.exception("agent run failed for %s; parking as %s", agent_id, status)
            await coordinator.set_status(agent_id, status)
            _consecutive_tool_errors.pop(agent_id, None)  # clear circuit breaker state
            await _notify_parent_on_terminal(coordinator, agent_id, status)
            if context.get("parent_id") is None and status in {"failed", "crashed"}:
                raise
            return None
        else:
            _provider_error_retries.pop(agent_id, None)  # clear retries on success
            _transport_error_retries.pop(agent_id, None)  # clear transport retries on success
            _consecutive_tool_errors.pop(agent_id, None)  # clear circuit breaker state
            await _settle_run_result(coordinator, agent_id, interactive)
            return stream


async def _settle_run_result(
    coordinator: AgentCoordinator,
    agent_id: str,
    interactive: bool,
) -> None:
    async with coordinator._lock:
        current_status = coordinator.statuses.get(agent_id)

    if current_status != "running":
        return

    if not interactive:
        return

    await coordinator.set_status(agent_id, "waiting")


async def _agent_status(coordinator: AgentCoordinator, agent_id: str) -> Status | None:
    async with coordinator._lock:
        return coordinator.statuses.get(agent_id)


def _final_output_preview(result: RunResultBase | None) -> str:
    final_output = getattr(result, "final_output", None)
    if final_output is None:
        return "<none>"
    text = str(final_output).replace("\n", " ").strip()
    if not text:
        return "<empty>"
    return text[:300]


async def _append_noninteractive_tool_required_message(
    *,
    session: Session | None,
    context: dict[str, Any],
    attempt: int,
    limit: int,
) -> list[dict[str, str]]:
    finish_tool = "finish_scan" if context.get("parent_id") is None else "agent_finish"
    message = (
        "Your previous response ended the autonomous prometheus run without a lifecycle tool call. "
        "That is invalid in non-interactive mode; plain text final answers are ignored. "
        "Continue immediately and call exactly one tool. "
        f"If your work is complete, call {finish_tool}. "
        "If you are blocked waiting for another agent, call wait_for_message. "
        "Otherwise use the appropriate execution or planning tool. "
        f"This is recovery attempt {attempt}/{limit}."
    )
    item = {"role": "user", "content": message}
    if session is None:
        return [item]

    await session.add_items([cast("TResponseInputItem", item)])
    return []


async def _notify_parent_on_terminal(
    coordinator: AgentCoordinator,
    agent_id: str,
    status: str,
) -> None:
    """Notify parent when a child agent reaches any terminal status."""
    if status not in ("crashed", "stopped", "failed"):
        return
    async with coordinator._lock:
        parent = coordinator.parent_of.get(agent_id)
        name = coordinator.names.get(agent_id, agent_id)
    if parent is None:
        return
    msg_type = "crash" if status == "crashed" else "completion"
    if status == "crashed":
        content = (
            f"[Agent crash] {name} ({agent_id}) terminated unexpectedly. "
            "Stop waiting on this child unless you want to message it again."
        )
    elif status == "stopped":
        content = (
            f"[Agent stopped] {name} ({agent_id}) hit a turn/circuit limit and was stopped. "
            "It did NOT call agent_finish. Check its output above or message it to resume. "
            "Do NOT keep waiting — it will not send a completion message."
        )
    else:  # failed
        content = (
            f"[Agent failed] {name} ({agent_id}) failed with an error. "
            "Stop waiting on this child unless you want to message it again."
        )
    await coordinator.send(
        parent,
        {
            "from": agent_id,
            "type": msg_type,
            "priority": "high",
            "content": content,
        },
    )


async def _start_child_runner(
    *,
    parent_ctx: dict[str, Any],
    coordinator: AgentCoordinator,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    child_agent: Any,
    child_id: str,
    name: str,
    parent_id: str | None,
    task: str,
    initial_input: Any,
    start_parked: bool = False,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> None:
    session = open_agent_session(child_id, agents_db_path)
    sessions_to_close.append(session)
    await coordinator.attach_runtime(child_id, session=session)

    # --- Circuit breaker: cap max_turns for child agents ---
    if max_turns > _MAX_CHILD_TURNS:
        logger.warning(
            "Capping max_turns for child %s (%s) from %d to %d",
            child_id,
            name,
            max_turns,
            _MAX_CHILD_TURNS,
        )
        max_turns = _MAX_CHILD_TURNS

    child_ctx: dict[str, Any] = dict(parent_ctx)
    child_ctx["agent_id"] = child_id
    child_ctx["parent_id"] = parent_id
    child_ctx["task"] = task

    task_handle = asyncio.create_task(
        run_agent_loop(
            agent=child_agent,
            initial_input=initial_input,
            run_config=run_config,
            context=child_ctx,
            max_turns=max_turns,
            coordinator=coordinator,
            agent_id=child_id,
            interactive=interactive,
            session=session,
            start_parked=start_parked,
            event_sink=event_sink,
            hooks=hooks,
        ),
        name=f"agent-{name}-{child_id}",
    )
    await coordinator.attach_runtime(child_id, task=task_handle)
