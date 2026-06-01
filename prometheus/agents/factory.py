"""Build SandboxAgents for root + child prometheus runs."""

from __future__ import annotations

import inspect
import json
import logging
import re
from typing import TYPE_CHECKING, Any

from agents.agent import ToolsToFinalOutputResult
from agents.sandbox import SandboxAgent
from agents.sandbox.capabilities import Filesystem, Shell
from agents.sandbox.errors import InvalidManifestPathError
from agents.tool import CustomTool, FunctionTool, Tool
from pydantic import ValidationError

from prometheus.agents.prompt import render_system_prompt
from prometheus.core.rate_limiter import maybe_rate_limit
from prometheus.core.comms import get_active_run, read_control, write_status
from prometheus.tools.agents_graph.tools import (
    agent_finish,
    create_agent,
    send_message_to_agent,
    stop_agent,
    view_agent_graph,
    wait_for_message,
)
from prometheus.tools.finish.tool import finish_scan
from prometheus.tools.load_skill.tool import load_skill
from prometheus.tools.notes.tools import (
    create_note,
    delete_note,
    get_note,
    list_notes,
    update_note,
)
from prometheus.tools.proxy.tools import (
    list_requests,
    list_sitemap,
    repeat_request,
    scope_rules,
    view_request,
    view_sitemap_entry,
)
from prometheus.tools.reporting.tool import create_vulnerability_report
from prometheus.tools.thinking.tool import think
from prometheus.tools.todo.tools import (
    create_todo,
    delete_todo,
    list_todos,
    mark_todo_done,
    mark_todo_pending,
    update_todo,
)
from prometheus.tools.web_search.tool import web_search
from prometheus.tools.threat_intel.tool import query_threat_feeds
from prometheus.tools.knowledge.tool import (
    save_knowledge,
    query_knowledge,
    search_knowledge,
    get_target_profile,
    list_target_profiles,
    update_report_status,
    get_report_details,
    list_reports,
    get_findings_summary,
    get_ready_to_submit,
    revalidate_findings,
)
from prometheus.tools.skill_learn.tool import (
    create_custom_skill,
    update_custom_skill,
    list_custom_skills,
    suggest_skill_update,
)
from prometheus.tools.coverage.tool import register_coverage, get_coverage_summary, get_untested_areas
from prometheus.tools.target_registry.tool import (
    add_target,
    remove_target,
    list_targets,
    update_target,
    get_target,
)
from prometheus.tools.cross_target.tool import get_cross_target_suggestions, get_tech_overlap
from prometheus.tools.scheduler.tool import (
    get_schedule,
    set_schedule,
    pause_schedule,
    resume_schedule,
)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from agents import RunContextWrapper
    from agents.tool import FunctionToolResult


logger = logging.getLogger(__name__)


_CUSTOM_TOOL_INPUT_FIELD_BY_NAME = {
    "apply_patch": "patch",
}
_DEFAULT_CUSTOM_TOOL_INPUT_FIELD = "input"

# --- Research gate: track mandatory pre-scan tool calls ---
# Only applies to root agent. Blocks finish_scan until both web_search
# and query_threat_feeds have been called at least once.
_research_gate_enabled = False
_research_calls: set[str] = set()
_RESEARCH_REQUIRED_TOOLS = {"web_search", "query_threat_feeds"}

# Per-technology CVE research gate: tracks how many technologies were
# passed to query_threat_feeds and requires at least that many web_search
# calls (capped at _MAX_TECH_RESEARCH) before allowing finish_scan.
_technologies_queried = 0
_web_search_count = 0
_MAX_TECH_RESEARCH = 5
_PER_TECH_GATE_ENABLED = False

# Nuclei gate: blocks finish_scan until nuclei has been run at least once
_nuclei_gate_enabled = False
_nuclei_run = False


def _enable_research_gate() -> None:
    global _research_gate_enabled, _research_calls
    global _PER_TECH_GATE_ENABLED, _technologies_queried, _web_search_count
    global _tor_gate_enabled, _tor_verified
    global _fingerprint_gate_enabled, _fingerprint_done
    _research_gate_enabled = True
    _research_calls = set()
    _PER_TECH_GATE_ENABLED = True
    _technologies_queried = 0
    _web_search_count = 0
    _tor_gate_enabled = True
    _tor_verified = False
    _fingerprint_gate_enabled = True
    _fingerprint_done = False


def _enable_nuclei_gate() -> None:
    global _nuclei_gate_enabled, _nuclei_run
    _nuclei_gate_enabled = True
    _nuclei_run = False


def _record_nuclei_run(cmd: str) -> None:
    """Record that nuclei was invoked (any command containing 'nuclei')."""
    global _nuclei_run
    if _nuclei_gate_enabled and "nuclei" in cmd.lower():
        _nuclei_run = True


def _record_research_call(tool_name: str) -> None:
    if _research_gate_enabled and tool_name in _RESEARCH_REQUIRED_TOOLS:
        _research_calls.add(tool_name)
    # Track web_search calls for per-technology gate
    if _PER_TECH_GATE_ENABLED and tool_name == "web_search":
        global _web_search_count
        _web_search_count += 1


def _research_complete() -> bool:
    return _RESEARCH_REQUIRED_TOOLS.issubset(_research_calls)


def _record_technologies_queried(count: int) -> None:
    """Record how many technologies were passed to query_threat_feeds."""
    global _technologies_queried
    _technologies_queried = max(_technologies_queried, count)


def _per_tech_research_complete() -> bool:
    """Check if web_search has been called at least once per queried technology."""
    required = min(_technologies_queried, _MAX_TECH_RESEARCH)
    return _web_search_count >= required


# --- Tor verification gate ---
_tor_gate_enabled = False
_tor_verified = False


def _enable_tor_gate() -> None:
    global _tor_gate_enabled, _tor_verified
    _tor_gate_enabled = True
    _tor_verified = False


def _record_tor_check(cmd: str, output: str = "") -> None:
    """Record that Tor was verified — only if IsTor:true is in the output.

    Previously this set _tor_verified=True just from seeing the command string,
    which meant a failed Tor check (exit code 7 / connection refused) would
    still pass the gate. Now we require the output to actually contain
    ``"IsTor":true``.
    """
    global _tor_verified
    if not _tor_gate_enabled:
        return
    if "check.torproject.org" not in cmd.lower() and "istor" not in cmd.lower():
        return
    # Only mark verified if the output actually confirms Tor
    if output and '"IsTor":true' in output:
        _tor_verified = True
        logger.info("Tor verification: IsTor=true confirmed")
    else:
        logger.warning(
            "Tor verification FAILED — command ran but IsTor:true not in output. "
            "Output was: %s", (output or "(empty)")[:200]
        )


# --- Tor proxy enforcement for individual commands ---
# Tools that MUST have an explicit proxy flag when making network requests.
# Format: {tool_name_in_command: set of acceptable proxy flag substrings}
_TOR_PROXY_FLAGS: dict[str, set[str]] = {
    "curl": {"--proxy", "--socks5", "--socks5h"},
    "httpx": {"-x ", "-proxy", "--proxy"},
    "nuclei": {"-proxy", "--proxy"},
    "sqlmap": {"--proxy", "--tor"},
    "ffuf": {"-x ", "-proxy", "--proxy"},
    "nikto": {"-useproxy"},
    "gobuster": {"-p ", "--proxy"},
    "katana": {"-proxy", "--proxy"},
    "subfinder": {"-proxy", "--proxy"},
    "arjun": {"--proxy"},
    "wpscan": {"--proxy"},
    "dirsearch": {"--proxy"},
    "wapiti": {"--proxy"},
}

# Tools that always go through Tor via env vars (ALL_PROXY) — no flag needed.
# These are safe because they respect HTTP_PROXY/ALL_PROXY environment variables
# and docker_client.py sets them to Tor.
_TOR_ENV_SAFE_TOOLS = {"nmap", "whatweb", "wappalyzer", "semgrep", "trivy", "gitleaks",
                       "trufflehog", "python", "python3", "pip", "gem", "go", "git"}


def _check_tor_proxy_required(cmd: str) -> str | None:
    """Check if a network command has explicit Tor proxy flags.

    Returns an error string if the command is blocked, or None if allowed.
    """
    if not _tor_gate_enabled:
        return None

    cmd_stripped = cmd.strip()
    cmd_lower = cmd_stripped.lower()

    # Skip non-network commands, local-only, and safe tools
    if cmd_lower.startswith(("ls", "cat", "grep", "find", "echo", "mkdir", "cp", "mv",
                             "rm", "touch", "chmod", "chown", "head", "tail", "wc",
                             "sort", "uniq", "awk", "sed", "tr", "cut", "tee",
                             "which", "whereis", "env", "export", "set", "unset",
                             "cd", "pwd", "man", "help", "type", "alias",
                             "nuclei -update", "nuclei -version", "nuclei --version")):
        return None

    # Check each tool that requires explicit proxy flags
    for tool_name, proxy_flags in _TOR_PROXY_FLAGS.items():
        # Match tool at start of command or after pipe/chain
        # Handles: "curl ...", "| curl ...", "&& curl ...", "; curl ..."
        tool_pattern = r'(?:^|[;&|]\s*)' + re.escape(tool_name) + r'(?:\s|$)'
        if not re.search(tool_pattern, cmd_lower):
            continue

        # Tool found — check if ANY proxy flag is present
        has_proxy = any(flag in cmd_stripped for flag in proxy_flags)
        if not has_proxy:
            return (
                f"TOR PROXY REQUIRED: '{tool_name}' must use an explicit Tor proxy flag. "
                f"Add one of: {', '.join(sorted(proxy_flags))} socks5://host.docker.internal:9050\n"
                f"Example for curl: curl --proxy socks5h://host.docker.internal:9050 <url>\n"
                f"Example for nuclei: nuclei -u <target> -proxy socks5://host.docker.internal:9050\n"
                f"ALL traffic MUST go through Tor. No exceptions."
            )

    return None


# --- Fingerprinting gate ---
_fingerprint_gate_enabled = False
_fingerprint_done = False
_FINGERPRINT_TOOLS = {"httpx", "whatweb", "wappalyzer", "nmap"}


def _enable_fingerprint_gate() -> None:
    global _fingerprint_gate_enabled, _fingerprint_done
    _fingerprint_gate_enabled = True
    _fingerprint_done = False


def _record_fingerprinting(cmd: str) -> None:
    """Record that a fingerprinting tool was used."""
    global _fingerprint_done
    if _fingerprint_gate_enabled:
        cmd_lower = cmd.lower()
        if any(tool in cmd_lower for tool in _FINGERPRINT_TOOLS):
            _fingerprint_done = True


def _custom_tool_input_field(tool: CustomTool) -> str:
    return _CUSTOM_TOOL_INPUT_FIELD_BY_NAME.get(tool.name, _DEFAULT_CUSTOM_TOOL_INPUT_FIELD)


def _raw_input_schema(tool: CustomTool) -> dict[str, Any]:
    input_field = _custom_tool_input_field(tool)
    return {
        "type": "object",
        "properties": {
            input_field: {
                "type": "string",
                "description": (
                    f"Complete `{tool.name}` payload. Follow the tool description exactly."
                ),
            },
        },
        "required": [input_field],
        "additionalProperties": False,
    }


def _extract_custom_input(tool: CustomTool, raw_input: str | dict[str, Any]) -> str:
    if isinstance(raw_input, str):
        try:
            parsed = json.loads(raw_input)
        except json.JSONDecodeError:
            return ""
    else:
        parsed = raw_input
    value = parsed.get(_custom_tool_input_field(tool))
    return value if isinstance(value, str) else ""


def _format_tool_error(exc: Exception) -> str:
    return str(exc) or exc.__class__.__name__


def _function_tool_with_error_result(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            return await invoke_tool(ctx, raw_input)
        except Exception as exc:  # noqa: BLE001 - tool errors should be model-visible results.
            logger.debug("Tool %s failed; returning error as result", tool.name, exc_info=True)
            return _format_tool_error(exc)

    tool.on_invoke_tool = invoke
    return tool


def _custom_tool_as_function_tool(tool: CustomTool) -> FunctionTool:
    async def invoke(ctx: Any, raw_input: str) -> Any:
        custom_input = _extract_custom_input(tool, raw_input)
        if not custom_input:
            return f"`{_custom_tool_input_field(tool)}` must be a non-empty string."
        try:
            return await tool.on_invoke_tool(ctx, custom_input)
        except Exception as exc:  # noqa: BLE001 - matches SDK CustomTool error-as-result behavior.
            logger.debug("Tool %s failed; returning error as result", tool.name, exc_info=True)
            return _format_tool_error(exc)

    needs_approval = tool.runtime_needs_approval()
    function_needs_approval: bool | Callable[[Any, dict[str, Any], str], Awaitable[bool]]
    if callable(needs_approval):

        async def approve(ctx: Any, args: dict[str, Any], call_id: str) -> bool:
            result = needs_approval(ctx, _extract_custom_input(tool, args), call_id)
            if inspect.isawaitable(result):
                result = await result
            return bool(result)

        function_needs_approval = approve
    else:
        function_needs_approval = needs_approval

    return FunctionTool(
        name=tool.name,
        description=(
            f"{tool.description}\n\n"
            f"Pass the complete `{tool.name}` payload in `{_custom_tool_input_field(tool)}`."
        ),
        params_json_schema=_raw_input_schema(tool),
        on_invoke_tool=invoke,
        strict_json_schema=False,
        needs_approval=function_needs_approval,
    )


def _configure_chat_completions_filesystem_tools(toolset: Any) -> None:
    for name, tool in vars(toolset).items():
        if isinstance(tool, CustomTool):
            setattr(toolset, name, _custom_tool_as_function_tool(tool))
        elif isinstance(tool, FunctionTool):
            setattr(toolset, name, _function_tool_with_error_result(tool))


_CHARS_ESCAPE_RE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0abtnvfr\\])")
_CHARS_ESCAPE_MAP = {
    "\\\\": "\\",
    "\\n": "\n",
    "\\t": "\t",
    "\\r": "\r",
    "\\0": "\x00",
    "\\a": "\x07",
    "\\b": "\x08",
    "\\v": "\x0b",
    "\\f": "\x0c",
}


def _decode_chars_escape(s: str) -> str:
    if "\\" not in s:
        return s

    def sub(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in _CHARS_ESCAPE_MAP:
            return _CHARS_ESCAPE_MAP[token]
        if token.startswith(("\\u", "\\x")):
            return chr(int(token[2:], 16))
        return token

    return _CHARS_ESCAPE_RE.sub(sub, s)


def _format_validation_error(tool_name: str, exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()))
        msg = err.get("msg", "invalid")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return f"{tool_name}: invalid arguments — " + "; ".join(parts)


def _wrap_exec_command(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        cmd = ""
        try:
            parsed = json.loads(raw_input) if isinstance(raw_input, str) else raw_input
            cmd = parsed.get("command", "") if isinstance(parsed, dict) else ""
        except Exception:
            logger.debug("Failed to parse raw_input for command extraction", exc_info=True)
        if cmd:
            try:
                wait_time = maybe_rate_limit(cmd)
                if wait_time > 0:
                    logger.debug("Rate limited: waited %.2fs for command: %s", wait_time, cmd[:80])
            except Exception:
                logger.debug("Rate limiter error for command: %s", cmd[:80], exc_info=True)
            # Track nuclei invocations for the nuclei gate
            _record_nuclei_run(cmd)
            # Track fingerprinting tools
            _record_fingerprinting(cmd)
            # Track Tor verification — MOVED to after execution so we can check output
            # _record_tor_check(cmd)  # OLD: marked verified just from seeing the command

            # --- Tor proxy enforcement (HARD BLOCK) ---
            # All network tools MUST use the Tor proxy explicitly.
            # This is code-level enforcement — not prompt-level.
            tor_block = _check_tor_proxy_required(cmd)
            if tor_block:
                logger.warning("Tor proxy enforcement blocked command: %s", cmd[:200])
                return tor_block
            # --- End Tor proxy enforcement ---

            # Defense-in-depth: detect agent trying to run query_threat_feeds as a shell command
            # instead of calling it as a proper tool. This wastes a step and won't satisfy the gate.
            if "query_threat_feeds" in cmd:
                logger.warning(
                    "Agent tried to run query_threat_feeds via exec_command (shell). "
                    "This is a TOOL, not a shell command. Command was: %s", cmd[:200]
                )
        run_id = get_active_run()
        if run_id and cmd:
            write_status(run_id, "tool_call", {"tool": "exec_command", "command": cmd[:200]})

        # Check for control messages from Hermes
        if run_id:
            try:
                # Read latest control messages (lightweight check)
                import pathlib
                ctrl_path = pathlib.Path.home() / ".prometheus" / "comms" / run_id / "control.jsonl"
                if ctrl_path.exists():
                    size = ctrl_path.stat().st_size
                    if size > 0:
                        msgs = read_control(run_id)
                        if msgs:
                            last = msgs[-1]
                            if last.get("action") == "stop":
                                return "SCAN STOPPED by Hermes agent: " + last.get("instruction", "")
            except Exception:
                logger.debug("Failed to read control messages for run %s", run_id, exc_info=True)

        try:
            result = await invoke_tool(ctx, raw_input)
            # Track Tor verification AFTER execution — check output for IsTor:true
            if cmd:
                _record_tor_check(cmd, str(result) if result else "")
            return result
        except ValidationError as exc:
            return _format_validation_error(tool.name, exc)
        except InvalidManifestPathError as exc:
            rel = exc.context.get("rel", "?")
            return (
                "exec_command: workdir must be a path inside /workspace "
                "(or omitted to use the turn's cwd). "
                f"Got: {rel!r}."
            )

    tool.on_invoke_tool = invoke
    return tool


def _wrap_write_stdin(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            parsed = json.loads(raw_input)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict) and isinstance(parsed.get("chars"), str):
            parsed["chars"] = _decode_chars_escape(parsed["chars"])
            raw_input = json.dumps(parsed)
        try:
            return await invoke_tool(ctx, raw_input)
        except ValidationError as exc:
            return _format_validation_error(tool.name, exc)

    tool.on_invoke_tool = invoke
    return tool


def _configure_shell_tools(toolset: Any, *, chat_completions: bool) -> None:
    for name, tool in vars(toolset).items():
        if not isinstance(tool, FunctionTool):
            continue
        wrapped = tool
        if tool.name == "exec_command":
            wrapped = _wrap_exec_command(wrapped)
        elif tool.name == "write_stdin":
            wrapped = _wrap_write_stdin(wrapped)
        if chat_completions:
            wrapped = _function_tool_with_error_result(wrapped)
        setattr(toolset, name, wrapped)


def _make_shell_configurator(*, chat_completions: bool) -> Any:
    def configure(toolset: Any) -> None:
        _configure_shell_tools(toolset, chat_completions=chat_completions)

    return configure


def _lifecycle_tool_completed(tool_name: str, output: Any) -> bool:
    if tool_name == "agent_finish":
        completion_key = "agent_completed"
    elif tool_name == "finish_scan":
        completion_key = "scan_completed"
    else:
        return False

    if not isinstance(output, str):
        return False
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError):
        return False
    return bool(isinstance(parsed, dict) and parsed.get("success") and parsed.get(completion_key))


def _wait_tool_parked(tool_name: str, output: Any) -> bool:
    if tool_name != "wait_for_message" or not isinstance(output, str):
        return False
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError):
        return False
    return bool(
        isinstance(parsed, dict)
        and parsed.get("success")
        and parsed.get("wait_outcome") == "waiting"
    )


def _wrap_query_threat_feeds_tool(tool: FunctionTool) -> FunctionTool:
    """Wrap query_threat_feeds to record how many technologies were queried."""
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        # Extract technology count from input before calling the tool
        try:
            parsed = json.loads(raw_input) if isinstance(raw_input, str) else raw_input
            if isinstance(parsed, dict):
                techs = parsed.get("technologies", [])
                if isinstance(techs, list):
                    _record_technologies_queried(len(techs))
        except Exception:
            logger.debug("Failed to extract technology count from query_threat_feeds input", exc_info=True)

        # Also record as a research call
        _record_research_call(tool.name)
        return await invoke_tool(ctx, raw_input)

    tool.on_invoke_tool = invoke
    return tool


def _wrap_research_tool(tool: FunctionTool) -> FunctionTool:
    """Wrap web_search/query_threat_feeds to record that research was done."""
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        _record_research_call(tool.name)
        return await invoke_tool(ctx, raw_input)

    tool.on_invoke_tool = invoke
    return tool


def _finish_tool_use_behavior(
    ctx: RunContextWrapper[Any],
    tool_results: list[FunctionToolResult],
) -> ToolsToFinalOutputResult:
    """Stop only after a lifecycle tool reports successful completion."""
    interactive = (
        bool(ctx.context.get("interactive", False)) if isinstance(ctx.context, dict) else False
    )
    for tool_result in tool_results:
        if _lifecycle_tool_completed(tool_result.tool.name, tool_result.output):
            # Tor gate: block finish_scan if Tor not verified
            if (
                _tor_gate_enabled
                and tool_result.tool.name == "finish_scan"
                and not _tor_verified
            ):
                logger.info("Tor gate: Tor verification not confirmed")
                return ToolsToFinalOutputResult(
                    is_final_output=False,
                    final_output="GATE BLOCKED: Tor verification not confirmed. "
                    "Run 'curl -s --proxy socks5h://host.docker.internal:9050 https://check.torproject.org/api/ip' "
                    "and verify the response contains 'IsTor: true'. This is MANDATORY before any scanning.",
                )
            # Fingerprinting gate: block research until technologies identified
            if (
                _fingerprint_gate_enabled
                and tool_result.tool.name == "finish_scan"
                and not _fingerprint_done
            ):
                logger.info("Fingerprint gate: no fingerprinting tools used")
                return ToolsToFinalOutputResult(
                    is_final_output=False,
                    final_output="GATE BLOCKED: No technology fingerprinting detected. "
                    "Run httpx, whatweb, or similar tools to identify the target's technology stack "
                    "BEFORE finishing. Example: 'httpx -u https://target.com -tech-detect'",
                )
            # Research gate: block finish_scan if mandatory research not done
            if (
                _research_gate_enabled
                and tool_result.tool.name == "finish_scan"
                and not _research_complete()
            ):
                missing = _RESEARCH_REQUIRED_TOOLS - _research_calls
                logger.info("Research gate: missing tools: %s", missing)
                return ToolsToFinalOutputResult(
                    is_final_output=False,
                    final_output=f"GATE BLOCKED: Mandatory research incomplete. "
                    f"Missing tool calls: {', '.join(missing)}. "
                    f"You MUST call both web_search and query_threat_feeds before finishing the scan.",
                )
            # Per-technology CVE research gate
            if (
                _PER_TECH_GATE_ENABLED
                and tool_result.tool.name == "finish_scan"
                and _technologies_queried > 0
                and not _per_tech_research_complete()
            ):
                required = min(_technologies_queried, _MAX_TECH_RESEARCH)
                logger.info(
                    "Per-tech research gate: %d/%d web_search calls for %d technologies",
                    _web_search_count, required, _technologies_queried,
                )
                return ToolsToFinalOutputResult(
                    is_final_output=False,
                    final_output=f"GATE BLOCKED: Per-technology CVE research incomplete. "
                    f"You've done {_web_search_count}/{required} web_search calls "
                    f"for {_technologies_queried} fingerprinted technologies. "
                    f"Search for CVEs for each technology before finishing.",
                )
            # Nuclei gate: block finish_scan if nuclei was never run
            if (
                _nuclei_gate_enabled
                and tool_result.tool.name == "finish_scan"
                and not _nuclei_run
            ):
                logger.info("Nuclei gate: nuclei was never invoked")
                return ToolsToFinalOutputResult(
                    is_final_output=False,
                    final_output="GATE BLOCKED: Nuclei was never run. "
                    "You MUST run nuclei at least once before finishing. "
                    "Example: 'nuclei -u https://target.com -proxy socks5://host.docker.internal:9050 "
                    "-severity high,critical -timeout 15 -retries 1 -no-interactsh -rate-limit 5 -c 10'",
                )
            return ToolsToFinalOutputResult(
                is_final_output=True,
                final_output=tool_result.output,
            )
        if interactive and _wait_tool_parked(tool_result.tool.name, tool_result.output):
            return ToolsToFinalOutputResult(
                is_final_output=True,
                final_output=tool_result.output,
            )
    return ToolsToFinalOutputResult(is_final_output=False, final_output=None)


_BASE_TOOLS: tuple[Tool, ...] = (
    think,
    load_skill,
    query_threat_feeds,
    create_todo,
    list_todos,
    update_todo,
    mark_todo_done,
    mark_todo_pending,
    delete_todo,
    create_note,
    list_notes,
    get_note,
    update_note,
    delete_note,
    web_search,
    create_vulnerability_report,
    list_requests,
    view_request,
    repeat_request,
    list_sitemap,
    view_sitemap_entry,
    scope_rules,
    view_agent_graph,
    send_message_to_agent,
    wait_for_message,
    create_agent,
    stop_agent,
    create_custom_skill,
    update_custom_skill,
    list_custom_skills,
    suggest_skill_update,
    save_knowledge,
    query_knowledge,
    search_knowledge,
    get_target_profile,
    list_target_profiles,
    update_report_status,
    get_report_details,
    list_reports,
    get_findings_summary,
    get_ready_to_submit,
    revalidate_findings,
    register_coverage,
    get_coverage_summary,
    get_untested_areas,
    add_target,
    remove_target,
    list_targets,
    update_target,
    get_target,
    get_schedule,
    set_schedule,
    pause_schedule,
    resume_schedule,
    get_cross_target_suggestions,
    get_tech_overlap,
)


def build_prometheus_agent(
    *,
    name: str = "prometheus",
    skills: list[str] | None = None,
    is_root: bool,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    interactive: bool = False,
    chat_completions_tools: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
) -> SandboxAgent[Any]:
    """Build a SandboxAgent for either root or child use.

    Args:
        chat_completions_tools: Wrap SDK custom tools as function tools
            when the selected backend cannot accept Responses custom tools.
    """
    instructions = render_system_prompt(
        skills=skills,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        is_root=is_root,
        interactive=interactive,
        system_prompt_context=system_prompt_context,
    )

    if is_root:
        tools: list[Tool] = [*_BASE_TOOLS, finish_scan]
        # Enable research gate for root agent — blocks finish_scan until
        # web_search and query_threat_feeds have been called at least once.
        _enable_research_gate()
        # Enable nuclei gate — blocks finish_scan until nuclei has been run
        _enable_nuclei_gate()
        # Enable Tor gate — blocks finish_scan until Tor is verified via check.torproject.org
        _enable_tor_gate()
        # Enable fingerprint gate — blocks finish_scan until technologies are identified
        _enable_fingerprint_gate()
    else:
        tools = [*_BASE_TOOLS, agent_finish]

    # Wrap research tools to track calls (for research gate)
    wrapped_tools: list[Tool] = []
    for t in tools:
        if isinstance(t, FunctionTool) and t.name == "query_threat_feeds":
            # Special wrapper that extracts technology count AND records research call
            wrapped_tools.append(_wrap_query_threat_feeds_tool(t))
        elif isinstance(t, FunctionTool) and t.name in _RESEARCH_REQUIRED_TOOLS:
            wrapped_tools.append(_wrap_research_tool(t))
        else:
            wrapped_tools.append(t)
    tools = wrapped_tools

    logger.info(
        "Built %s agent '%s' (skills=%d, tools=%d, scan_mode=%s, whitebox=%s)",
        "root" if is_root else "child",
        name,
        len(skills or []),
        len(tools),
        scan_mode,
        is_whitebox,
    )

    return SandboxAgent(
        name=name,
        instructions=instructions,
        tools=tools,
        tool_use_behavior=_finish_tool_use_behavior,
        reset_tool_choice=interactive,
        model=None,
        capabilities=[
            Filesystem(
                configure_tools=(
                    _configure_chat_completions_filesystem_tools if chat_completions_tools else None
                ),
            ),
            Shell(
                configure_tools=_make_shell_configurator(
                    chat_completions=chat_completions_tools,
                ),
            ),
        ],
    )


def make_child_factory(
    *,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    interactive: bool = False,
    chat_completions_tools: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
) -> Any:
    """Return the runner-owned builder used by ``spawn_child_agent``.

    Run-level arguments (``scan_mode``, ``is_whitebox``, etc.) are
    captured in a closure so each child inherits scan-level configuration
    without the graph tool knowing about runner internals.
    """

    def _factory(*, name: str, skills: list[str]) -> SandboxAgent[Any]:
        return build_prometheus_agent(
            name=name,
            skills=skills,
            is_root=False,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=system_prompt_context,
        )

    return _factory
