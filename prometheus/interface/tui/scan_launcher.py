"""Scan launcher modal screen for the prometheus TUI."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from textual.containers import Grid, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Select, TextArea


if TYPE_CHECKING:
    from textual import events
    from textual.app import ComposeResult


RATE_LIMIT_OPTIONS = [
    ("No Limit", 0),
    ("5 req/s", 5),
    ("10 req/s", 10),
    ("20 req/s", 20),
    ("50 req/s", 50),
]


class ScanLauncherScreen(ModalScreen[dict[str, Any] | None]):  # type: ignore[misc]
    """Modal screen for configuring and launching a new scan.

    Returns a config dict on launch or ``None`` on cancel.
    """

    CSS = """
    ScanLauncherScreen {
        align: center middle;
        background: #000000 80%;
    }

    #scan_launcher_dialog {
        grid-size: 1 3;
        grid-rows: auto 1fr auto;
        padding: 1 3;
        width: 70;
        max-width: 90;
        height: 80%;
        border: solid #262626;
        background: #0a0a0a;
    }

    #scan_launcher_title {
        color: #22c55e;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }

    #scan_launcher_form {
        height: 1fr;
        background: transparent;
        padding: 0;
    }

    .scan-field-label {
        color: #a8a29e;
        margin-top: 1;
        margin-bottom: 0;
    }

    #scan_target {
        height: 3;
        background: #1a1a1a;
        color: #d4d4d4;
        border: round #333333;
        margin: 0;
    }

    #scan_target:focus {
        border: round #22c55e;
    }

    #scan_target > .text-area--placeholder {
        color: #525252;
        text-style: italic;
    }

    #scan_target > .text-area--cursor {
        color: #22c55e;
        background: #22c55e;
    }

    #scan_mode {
        background: transparent;
        color: #d4d4d4;
        border: round #333333;
        margin: 0;
        min-height: 3;
    }

    #scan_mode:focus {
        border: round #22c55e;
    }

    #scan_instructions {
        height: 3;
        background: #1a1a1a;
        color: #d4d4d4;
        border: round #333333;
        margin: 0;
    }

    #scan_instructions:focus {
        border: round #22c55e;
    }

    #scan_instructions > .text-area--placeholder {
        color: #525252;
        text-style: italic;
    }

    #scan_instructions > .text-area--cursor {
        color: #22c55e;
        background: #22c55e;
    }

    #scan_headers {
        height: 3;
        background: #1a1a1a;
        color: #d4d4d4;
        border: round #333333;
        margin: 0;
    }

    #scan_headers:focus {
        border: round #22c55e;
    }

    #scan_headers > .text-area--placeholder {
        color: #525252;
        text-style: italic;
    }

    #scan_headers > .text-area--cursor {
        color: #22c55e;
        background: #22c55e;
    }

    #scan_rate_limit {
        background: transparent;
        color: #d4d4d4;
        border: round #333333;
        margin: 0;
        min-height: 3;
    }

    #scan_rate_limit:focus {
        border: round #22c55e;
    }

    #scan_launcher_buttons {
        grid-size: 2;
        grid-gutter: 1;
        grid-columns: 1fr 1fr;
        width: 100%;
        height: auto;
        margin-top: 1;
        padding-top: 1;
        border-top: solid #1a1a1a;
    }

    #scan_launcher_buttons Button {
        height: 3;
        min-height: 3;
        border: none;
        text-style: bold;
    }

    #launch_scan {
        background: transparent;
        color: #22c55e;
        border: none;
    }

    #launch_scan:hover, #launch_scan:focus {
        background: #22c55e;
        color: #000000;
        border: none;
    }

    #cancel_scan {
        background: transparent;
        color: #737373;
        border: none;
    }

    #cancel_scan:hover, #cancel_scan:focus {
        background: #333333;
        color: #ffffff;
        border: none;
    }
    """

    def compose(self) -> ComposeResult:
        yield Grid(
            Label("🚀 Launch New Scan", id="scan_launcher_title"),
            VerticalScroll(
                Label("Target *", classes="scan-field-label"),
                TextArea(
                    id="scan_target",
                    placeholder="Enter target URL, domain, IP, or path",
                ),
                Label("Scan Mode", classes="scan-field-label"),
                Select(
                    [("Quick", "quick"), ("Standard", "standard"), ("Deep", "deep")],
                    id="scan_mode",
                    value="deep",
                    allow_blank=False,
                ),
                Label("Instructions", classes="scan-field-label"),
                TextArea(
                    id="scan_instructions",
                    placeholder="Custom instructions (optional)",
                ),
                Label("Custom Headers", classes="scan-field-label"),
                TextArea(
                    id="scan_headers",
                    placeholder="Key: Value, one per line (optional)",
                ),
                Label("Rate Limit", classes="scan-field-label"),
                Select(
                    RATE_LIMIT_OPTIONS,
                    id="scan_rate_limit",
                    value=5,
                    allow_blank=False,
                ),
                id="scan_launcher_form",
            ),
            Grid(
                Button("[ Ctrl+Enter ] Launch", variant="success", id="launch_scan"),
                Button("[ Esc ] Cancel", variant="default", id="cancel_scan"),
                id="scan_launcher_buttons",
            ),
            id="scan_launcher_dialog",
        )

    def on_mount(self) -> None:
        """Focus the target input on mount."""
        target = self.query_one("#scan_target", TextArea)
        target.focus()

    def on_key(self, event: events.Key) -> None:
        """Handle key events — ESC to cancel, ctrl+enter to launch."""
        if event.key == "escape":
            self.dismiss(None)
            event.prevent_default()
        elif event.key == "ctrl+enter":
            self._do_launch()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "launch_scan":
            self._do_launch()
        elif event.button.id == "cancel_scan":
            self.dismiss(None)

    def _do_launch(self) -> None:
        """Validate mandatory fields and dismiss with the scan config dict."""
        target = self.query_one("#scan_target", TextArea).text.strip()
        if not target:
            self.notify("Target is required", severity="error")
            self.query_one("#scan_target", TextArea).focus()
            return

        scan_mode: str = self.query_one("#scan_mode", Select).value  # type: ignore[assignment]
        instructions = self.query_one("#scan_instructions", TextArea).text.strip()
        headers_text = self.query_one("#scan_headers", TextArea).text.strip()
        rate_limit: int = self.query_one("#scan_rate_limit", Select).value  # type: ignore[assignment]

        custom_headers: list[dict[str, str]] = []
        if headers_text:
            for line in headers_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip()
                    value = value.strip()
                    if key and value:
                        custom_headers.append({"key": key, "value": value})

        config: dict[str, Any] = {
            "target": target,
            "scan_mode": scan_mode,
            "instructions": instructions,
            "custom_headers": custom_headers,
            "rate_limit": rate_limit,
        }

        self.dismiss(config)
