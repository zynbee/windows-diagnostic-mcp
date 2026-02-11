"""MCP Client test script — exercises every tool registered on the server.

Usage:
    uv run python tests/test_mcp_client.py                  # run safe (fast) tools only
    uv run python tests/test_mcp_client.py --all            # run ALL tools including slow ones
    uv run python tests/test_mcp_client.py --tool hw_cpu_info  # run a single tool by name
"""

import asyncio
import argparse
import sys
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# ---------------------------------------------------------------------------
# Tool definitions: (tool_name, kwargs, slow?)
# slow tools are skipped unless --all is passed
# ---------------------------------------------------------------------------
TOOLS: list[tuple[str, dict, bool]] = [
    # ── Hardware ──────────────────────────────────────────────────────────
    ("hw_cpu_info",        {},                          False),
    ("hw_memory_info",     {},                          False),
    ("hw_gpu_info",        {},                          False),
    ("hw_disk_health",     {"drive_index": 0},          False),
    ("hw_battery_health",  {},                          False),
    ("hw_sensor_readings", {},                          False),
    ("hw_disk_benchmark",  {"drive_letter": "C", "duration_seconds": 5}, True),

    # ── Network ───────────────────────────────────────────────────────────
    ("net_connectivity_test",  {"target": "8.8.8.8"},   False),
    ("net_dns_diagnostics",    {"domain": "www.google.com"}, False),
    ("net_adapter_info",       {},                      False),
    ("net_firewall_status",    {},                      False),
    ("net_active_connections",  {"state": "Established"}, False),
    ("net_wifi_diagnostics",   {},                      False),
    ("net_speed_test",         {},                      True),

    # ── OS ────────────────────────────────────────────────────────────────
    ("os_system_info",         {},                      False),
    ("os_event_log_errors",    {"log_name": "System", "hours_back": 24, "max_events": 10}, False),
    ("os_dism_health",         {"scan_type": "CheckHealth"}, False),
    ("os_windows_updates",     {"last_n": 5},           False),
    ("os_driver_status",       {},                      False),
    ("os_installed_software",  {"search": "Python"},    False),
    ("os_startup_programs",    {},                      False),
    ("os_sfc_scan",            {},                      True),

    # ── Performance ───────────────────────────────────────────────────────
    ("perf_system_snapshot",   {},                      False),
    ("perf_top_processes",     {"top_n": 10, "sort_by": "CPU"}, False),
    ("perf_memory_analysis",   {},                      False),
    ("perf_disk_io",           {},                      False),
    ("perf_boot_analysis",     {},                      False),
    ("perf_service_health",    {},                      False),

    # ── Security ──────────────────────────────────────────────────────────
    ("sec_defender_status",    {},                      False),
    ("sec_bitlocker_status",   {},                      False),
    ("sec_local_users",        {},                      False),
    ("sec_audit_policy",       {},                      False),
    ("sec_open_ports",         {},                      False),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Test all MCP server tools via stdio client")
    parser.add_argument("--all", action="store_true", help="Include slow / long-running tools")
    parser.add_argument("--tool", type=str, default=None, help="Run a single tool by name")
    parser.add_argument("--timeout", type=int, default=120, help="Per-tool timeout in seconds (default: 120)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print full tool output")
    return parser.parse_args()


def build_tool_list(args: argparse.Namespace) -> list[tuple[str, dict, bool]]:
    if args.tool:
        matches = [(n, kw, s) for n, kw, s in TOOLS if n == args.tool]
        if not matches:
            print(f"Unknown tool: {args.tool}")
            print(f"Available tools: {', '.join(n for n, _, _ in TOOLS)}")
            sys.exit(1)
        return matches
    if args.all:
        return TOOLS
    return [(n, kw, s) for n, kw, s in TOOLS if not s]


async def run_tests(args: argparse.Namespace) -> None:
    project_dir = str(Path(__file__).resolve().parent.parent)

    server_params = StdioServerParameters(
        command="uv",
        args=["run", "windows-diagnostic-mcp", "--mode", "stdio"],
        cwd=project_dir,
    )

    tools_to_run = build_tool_list(args)
    passed = 0
    failed = 0
    skipped = 0
    results: list[tuple[str, str, float, str]] = []  # (name, status, elapsed, detail)

    print(f"Connecting to MCP server (cwd: {project_dir}) ...")
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # ── List tools ────────────────────────────────────────────
            tool_list = await session.list_tools()
            server_tool_names = {t.name for t in tool_list.tools}
            print(f"Server reports {len(server_tool_names)} tools: {', '.join(sorted(server_tool_names))}\n")

            # ── Run each tool ─────────────────────────────────────────
            for tool_name, kwargs, is_slow in tools_to_run:
                if tool_name not in server_tool_names:
                    print(f"  SKIP  {tool_name} (not registered on server)")
                    results.append((tool_name, "SKIP", 0, "not registered"))
                    skipped += 1
                    continue

                print(f"  RUN   {tool_name} ...", end="", flush=True)
                t0 = time.perf_counter()
                try:
                    result = await asyncio.wait_for(
                        session.call_tool(tool_name, kwargs),
                        timeout=args.timeout,
                    )
                    elapsed = time.perf_counter() - t0

                    # call_tool returns a CallToolResult with .content list
                    text_parts = []
                    for block in result.content:
                        if hasattr(block, "text"):
                            text_parts.append(block.text)

                    output = "\n".join(text_parts)
                    is_error = result.isError if hasattr(result, "isError") else False

                    if is_error:
                        print(f" FAIL ({elapsed:.1f}s)")
                        results.append((tool_name, "FAIL", elapsed, output[:200]))
                        failed += 1
                    else:
                        print(f" OK   ({elapsed:.1f}s)")
                        results.append((tool_name, "OK", elapsed, output[:200]))
                        passed += 1

                    if args.verbose:
                        for line in output.splitlines():
                            print(f"        {line}")
                        print()

                except asyncio.TimeoutError:
                    elapsed = time.perf_counter() - t0
                    print(f" TIMEOUT ({elapsed:.1f}s)")
                    results.append((tool_name, "TIMEOUT", elapsed, ""))
                    failed += 1

                except Exception as exc:
                    elapsed = time.perf_counter() - t0
                    print(f" ERROR ({elapsed:.1f}s): {exc}")
                    results.append((tool_name, "ERROR", elapsed, str(exc)))
                    failed += 1

    # ── Summary ───────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    print(f"{'Tool':<30} {'Status':<10} {'Time':>8}")
    print("-" * 70)
    for name, status, elapsed, detail in results:
        status_display = status
        if status == "OK":
            status_display = "OK"
        elif status == "FAIL":
            status_display = "FAIL"
        elif status == "TIMEOUT":
            status_display = "TIMEOUT"
        elif status == "ERROR":
            status_display = "ERROR"
        elif status == "SKIP":
            status_display = "SKIP"
        print(f"{name:<30} {status_display:<10} {elapsed:>7.1f}s")

    print("-" * 70)
    total = passed + failed + skipped
    print(f"Total: {total}  |  Passed: {passed}  |  Failed: {failed}  |  Skipped: {skipped}")

    if failed:
        print("\nFailed tools:")
        for name, status, _, detail in results:
            if status in ("FAIL", "TIMEOUT", "ERROR"):
                print(f"  {name}: {detail[:120]}")

    print()
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(run_tests(args))
