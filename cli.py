#!/usr/bin/env python3
"""
Vulnerability Tracker CLI — cli.py
Author : Krishnakanth B.
Role   : DevSecOps / Full Stack Developer

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHY use `rich` for terminal output?

The same library powers Semgrep, Checkov, and
Prowler — the most widely used open-source security
CLI tools in the industry.

Color-coding by risk type is functional, not cosmetic.
When a developer is looking at 50 findings, color
grouping lets them triage faster. That's a security
outcome, not an aesthetic preference.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Commands:
  python cli.py get                    Fetch all, sorted newest first
  python cli.py post                   POST bundled demo entries
  python cli.py post --file vulns.json POST from a JSON file
  python cli.py get --format json      Raw JSON (pipeline-friendly)
  python cli.py get --url <url>        Target a different server
"""

import argparse
import json
import sys
from datetime import datetime

import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Console is the main Rich object — all output goes through it.
# This means we can redirect output in tests by passing a
# different console, rather than patching sys.stdout everywhere.
console = Console()

DEFAULT_URL = "http://127.0.0.1:8000/api/v1/vulnerabilities"

# ─────────────────────────────────────────────────
# RISK COLOR MAP
#
# Colors mirror industry-standard severity tiers.
# This is the same mental model used by CVSS scoring,
# Snyk, and Dependabot severity labels.
#
# bold red    = Critical (RCE, deserialization)
#              → execute arbitrary code on the host
# red         = High (injection)
#              → extract or corrupt data
# dark_orange = High-Medium (auth bypass, SSRF,
#               supply chain)
#              → bypass controls or reach internal systems
# orange3     = Medium (request smuggling)
#              → bypass proxies and WAFs
# yellow      = Medium-Low (access control, XXE)
#              → access unauthorized data
# cyan        = Informational (platform issues)
#              → platform-level findings, not exploits
#
# The "white" default handles unknown types gracefully
# without crashing — new vulnerability types still display.
# ─────────────────────────────────────────────────

TYPE_COLORS: dict[str, str] = {
    "Remote Code Execution":       "bold red",
    "Injection":                   "red",
    "Deserialization":             "bold red",
    "Authentication Bypass":       "dark_orange",
    "Server-Side Request Forgery": "dark_orange",
    "Supply Chain":                "dark_orange",
    "Request Smuggling":           "orange3",
    "Access Control":              "yellow",
    "XML External Entity":         "yellow",
    "Platform":                    "cyan",
}

# Tracks names of vulnerabilities added via POST in this session.
# Used to show a visual NEW badge on those rows in the GET output.
# This is a UX decision — the engineer who posted something
# wants confirmation it actually landed in the right place.
# A set is used (not a list) because membership check is O(1).
_session_added: set[str] = set()

# Two new real-world CVEs bundled for the POST demo.
# Using real entries (not "test1", "test2") demonstrates
# domain awareness and makes the demo meaningful.
DEMO_ENTRIES = [
    {
        "name":        "XZ Utils Backdoor",
        "type":        "Supply Chain",
        "description": "Malicious code injected into XZ Utils 5.6.x enabling unauthorized SSH access on Linux.",
        "date":        "2024-03-29",
    },
    {
        "name":        "HTTP Request Smuggling",
        "type":        "Request Smuggling",
        "description": "Ambiguous HTTP/1.1 framing used to bypass front-end security controls and poison caches.",
        "date":        "2023-09-18",
    },
]


# ─────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────

def _color(vuln_type: str) -> str:
    """
    Returns Rich markup color for a given vulnerability type.
    Falls back to 'white' for unknown types — new types won't crash the CLI.
    """
    return TYPE_COLORS.get(vuln_type, "white")


def _parse_date(date_str: str) -> datetime:
    """
    Safe date parser for sorting.

    WHY not just sort the string directly?
    ISO-8601 strings ("2023-01-01") DO sort correctly
    as strings for the YYYY-MM-DD format. However, if
    a date ever includes a time component or a different
    format, string sort silently produces wrong results.
    datetime.strptime makes the contract explicit and
    raises an error rather than silently misbehaving.

    Returns datetime.min on failure so malformed dates
    sort to the BOTTOM rather than crashing the whole
    display call.
    """
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except (ValueError, TypeError):
        return datetime.min  # Sorts to bottom — silent degradation, not crash


def _make_request(method: str, url: str, **kwargs) -> requests.Response:
    """
    Centralised HTTP transport with consistent error handling.

    WHY centralize this instead of try/catch in each command?

    1. Error handling is in ONE place — not duplicated across
       every command. If we need to add retry logic, auth
       headers, or TLS certificates, we do it once here.

    2. Commands stay focused on what to do with a SUCCESSFUL
       response. They don't need to know about network failures.

    3. Error messages are consistent across all commands.
       A user sees the same clear message whether GET or
       POST failed to connect.

    This is the same pattern used in real CLIs like the
    AWS CLI and GitHub CLI for their HTTP layers.
    """
    try:
        response = requests.request(method, url, timeout=10, **kwargs)
        response.raise_for_status()
        return response

    except requests.ConnectionError:
        # The server is not running — most common failure mode
        console.print(Panel(
            "[bold red]Connection refused.[/bold red]\n\n"
            "The API server is not running.\n"
            "Start it:  [bold]python server.py[/bold]",
            title="[red]Connection Error[/red]",
            border_style="red",
        ))
        sys.exit(1)

    except requests.HTTPError as exc:
        # Server responded but with an error status (4xx / 5xx)
        # Try to extract the "detail" field from FastAPI's error body
        detail = exc.response.text
        try:
            detail = json.loads(detail).get("detail", detail)
        except (json.JSONDecodeError, AttributeError):
            pass  # If not JSON, show raw text — still useful
        console.print(Panel(
            f"[bold red]HTTP {exc.response.status_code}[/bold red] — {detail}",
            title="[red]API Error[/red]",
            border_style="red",
        ))
        sys.exit(1)

    except requests.Timeout:
        # Server is running but not responding in time
        console.print("[bold red]✗ Request timed out (10s).[/bold red]")
        sys.exit(1)


def _render_table(results: list[dict]) -> None:
    """
    Sort by date descending and render as a Rich colored table.

    WHY sort in the CLI and not the server?
    The spec explicitly asks the CLI to sort the GET response.
    Different consumers of the same API might want different
    sort orders (by type, by name, by date ascending).
    Sorting server-side locks every caller into one order.
    The API returns data; the client decides presentation.
    """
    # Sort newest first — reverse=True gives descending order
    sorted_results = sorted(
        results,
        key=lambda x: _parse_date(x.get("date", "")),
        reverse=True,
    )

    table = Table(
        box=box.ROUNDED,           # Clean rounded borders
        border_style="bright_black",
        header_style="bold white on dark_blue",
        show_lines=True,           # Row dividers improve readability for long descriptions
        expand=False,              # Don't stretch to terminal width — data drives width
    )

    # Column definitions — widths chosen so a typical terminal (120 chars)
    # shows the full table without wrapping
    table.add_column("Date",        width=12,  no_wrap=True)
    table.add_column("Name",        min_width=28)
    table.add_column("Type",        min_width=24, no_wrap=True)
    table.add_column("Description", min_width=40)

    for i, r in enumerate(sorted_results):
        c    = _color(r["type"])
        name = r["name"]
        desc = r["description"]

        # Truncate long descriptions to prevent table from
        # wrapping across multiple terminal lines
        if len(desc) > 72:
            desc = desc[:69] + "..."

        # ★ marks the most recent entry (index 0 after sort)
        # Gives the reader an immediate anchor — "this is the newest"
        date_cell = f"[dim]{r['date']}[/dim]"
        if i == 0:
            date_cell = f"[bold green]{r['date']}[/bold green] [green]★[/green]"

        # NEW badge for anything posted in this CLI session.
        # The engineer who ran `post` gets visual confirmation
        # that their entries landed exactly where they expected.
        if name in _session_added:
            name = f"{name} [bold green on dark_green] NEW [/bold green on dark_green]"

        table.add_row(
            date_cell,
            f"[{c}]{name}[/{c}]",         # Color = risk level
            f"[{c}]{r['type']}[/{c}]",    # Color = risk level (consistent with name)
            f"[dim]{desc}[/dim]",          # Dim description — name/type are the focus
        )

    console.print(table)

    # Legend below the table explains the color coding to
    # anyone who hasn't seen this CLI before
    console.print(
        f"  [dim]{len(sorted_results)} record(s)  ·  "
        f"sorted [bold]newest → oldest[/bold]  ·  "
        f"[bold red]■[/bold red] Critical  "
        f"[dark_orange]■[/dark_orange] High  "
        f"[yellow]■[/yellow] Elevated  "
        f"[cyan]■[/cyan] Info[/dim]\n"
    )


# ─────────────────────────────────────────────────
# COMMANDS
# ─────────────────────────────────────────────────

def cmd_get(url: str, output_format: str = "table") -> None:
    """Fetch all records and display sorted by date descending."""

    # Panel header makes it instantly clear what operation is happening
    console.print(Panel(
        f"[bold cyan]GET[/bold cyan]  {url}",
        title="[bold]Vulnerability Tracker[/bold]",
        border_style="cyan",
        padding=(0, 2),
    ))

    # Spinner shows the user something is happening during network I/O.
    # Without it, a slow server looks like the CLI has frozen.
    with console.status("[cyan]Fetching records...[/cyan]", spinner="dots"):
        resp = _make_request("GET", url)

    data    = resp.json()
    results = data.get("results", [])

    if not results:
        console.print("[yellow]No records found.[/yellow]")
        return

    if output_format == "json":
        # Raw JSON mode — useful for piping to jq, grep, or other tools.
        # A CLI that only outputs pretty tables is useless in automation.
        # console.print_json handles indentation and syntax highlighting.
        console.print_json(json.dumps(results, indent=2))
        return

    _render_table(results)


def cmd_post(url: str, payload: list[dict]) -> None:
    """POST new records, then automatically re-fetch the full sorted list."""

    console.print(Panel(
        f"[bold green]POST[/bold green] {url}\n"
        f"[dim]Submitting [bold]{len(payload)}[/bold] new record(s)...[/dim]",
        title="[bold]Add Vulnerabilities[/bold]",
        border_style="green",
        padding=(0, 2),
    ))

    with console.status("[green]Sending...[/green]", spinner="dots"):
        resp = _make_request(
            "POST",
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )

    added = resp.json().get("results", [])

    console.print(f"\n  [bold green]✓ {len(added)} record(s) added:[/bold green]")
    for item in added:
        c = _color(item["type"])
        console.print(
            f"    [{c}]●[/{c}]  [{c}]{item['name']}[/{c}]"
            f"  [dim]({item['type']} · {item['date']})[/dim]"
        )
        # Register this name so the next GET call marks it NEW
        _session_added.add(item["name"])

    # Automatically re-fetch after POST — the spec asks us to
    # sort and display GET results, and this confirms the POST
    # actually landed and is visible in the full collection
    console.print()
    console.rule("[dim]Updated collection (GET after POST)[/dim]")
    cmd_get(url)


# ─────────────────────────────────────────────────
# ENTRY POINT + ARGUMENT PARSING
# ─────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Vulnerability Tracker CLI — Paylocity DevSecOps Exercise",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python cli.py get\n"
            "  python cli.py get --format json\n"
            "  python cli.py post\n"
            "  python cli.py post --file my_vulns.json\n"
            "  python cli.py get --url http://staging:8000/api/v1/vulnerabilities\n"
        ),
    )

    parser.add_argument(
        "command",
        choices=["get", "post"],
        help="API operation to perform",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        metavar="URL",
        help=f"API endpoint URL (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        # WHY offer json format?
        # A CLI that only does pretty output is useless in scripts.
        # Security engineers pipe CLI output into log aggregators,
        # Slack webhooks, and report generators.
        help="Output format for GET — table (default) or raw JSON",
    )
    parser.add_argument(
        "--file",
        default=None,
        metavar="PATH",
        help="JSON file with an array of vulnerability DTOs (POST only)",
    )

    args = parser.parse_args()

    if args.command == "get":
        cmd_get(args.url, output_format=args.format)

    elif args.command == "post":
        if args.file:
            # Load payload from file — allows batch importing from
            # external scanners, SIEM exports, or other tools
            try:
                with open(args.file) as f:
                    payload = json.load(f)
                if not isinstance(payload, list):
                    # Give a clear, actionable error message.
                    # "Invalid input" is not actionable.
                    # "Must be an array [ {...}, ... ]" is.
                    console.print(
                        "[bold red]✗[/bold red] JSON file must contain an array  "
                        "[dim][ {{...}}, {{...}} ][/dim]"
                    )
                    sys.exit(1)
            except FileNotFoundError:
                console.print(f"[bold red]✗ File not found:[/bold red] {args.file}")
                sys.exit(1)
            except json.JSONDecodeError as exc:
                console.print(f"[bold red]✗ Invalid JSON:[/bold red] {exc}")
                sys.exit(1)
        else:
            # No file provided — use bundled demo entries
            payload = DEMO_ENTRIES

        cmd_post(args.url, payload)


if __name__ == "__main__":
    main()