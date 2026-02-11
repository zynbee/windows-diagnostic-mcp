"""Operating System diagnostic tools for Windows."""

import json
import logging

from fastmcp import FastMCP

from ..utils.command_runner import run_powershell, run_command

logger = logging.getLogger(__name__)


def register_os_tools(mcp: FastMCP):
    """Register all OS diagnostic tools with the MCP server."""

    @mcp.tool(name="os_system_info", tags={"os"})
    async def system_info() -> str:
        """
        Get comprehensive system information including OS version, build,
        install date, hostname, domain, and uptime.
        """
        result = await run_powershell(
            "$ci = Get-ComputerInfo | Select-Object "
            "CsName, CsDomain, OsName, OsVersion, OsBuildNumber, "
            "OsArchitecture, OsInstallDate, OsLastBootUpTime, "
            "OsUptime, WindowsVersion, WindowsEditionId, "
            "BiosManufacturer, BiosSMBIOSBIOSVersion, "
            "CsSystemType, CsTotalPhysicalMemory, CsNumberOfProcessors, "
            "CsNumberOfLogicalProcessors, TimeZone; "
            "$ci | ConvertTo-Json"
        )
        if result.return_code != 0:
            return f"Failed to get system info: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"System Info (raw):\n{result.stdout}"

        output = "System Information:\n\n"
        output += f"Hostname: {data.get('CsName', 'Unknown')}\n"
        output += f"Domain: {data.get('CsDomain', 'Unknown')}\n"
        output += f"OS: {data.get('OsName', 'Unknown')}\n"
        output += f"Version: {data.get('OsVersion', 'Unknown')}\n"
        output += f"Build: {data.get('OsBuildNumber', 'Unknown')}\n"
        output += f"Architecture: {data.get('OsArchitecture', 'Unknown')}\n"
        output += f"Edition: {data.get('WindowsEditionId', 'Unknown')}\n"
        output += f"Install Date: {data.get('OsInstallDate', 'Unknown')}\n"
        output += f"Last Boot: {data.get('OsLastBootUpTime', 'Unknown')}\n"

        uptime = data.get("OsUptime", {})
        if isinstance(uptime, dict):
            days = uptime.get("Days", 0)
            hours = uptime.get("Hours", 0)
            mins = uptime.get("Minutes", 0)
            output += f"Uptime: {days}d {hours}h {mins}m\n"

        output += f"System Type: {data.get('CsSystemType', 'Unknown')}\n"
        total_mem = data.get("CsTotalPhysicalMemory", 0)
        if total_mem:
            output += f"Total RAM: {int(total_mem) / (1024**3):.1f} GB\n"
        output += f"Processors: {data.get('CsNumberOfProcessors', '?')}\n"
        output += f"Logical CPUs: {data.get('CsNumberOfLogicalProcessors', '?')}\n"
        output += f"BIOS: {data.get('BiosManufacturer', '?')} {data.get('BiosSMBIOSBIOSVersion', '')}\n"
        output += f"Time Zone: {data.get('TimeZone', 'Unknown')}\n"
        return output

    @mcp.tool(name="os_event_log_errors", tags={"os"})
    async def event_log_errors(
        log_name: str = "System",
        hours_back: int = 24,
        max_events: int = 50,
    ) -> str:
        """
        Get recent critical and error events from Windows Event Logs.

        Args:
            log_name: Event log to query — System, Application, or Security (default: System).
            hours_back: How many hours back to search (default: 24).
            max_events: Maximum number of events to return (default: 50).
        """
        result = await run_powershell(
            f"Get-WinEvent -FilterHashtable @{{"
            f"LogName='{log_name}'; Level=1,2; "
            f"StartTime=(Get-Date).AddHours(-{hours_back})"
            f"}} -MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            f"Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | "
            f"ConvertTo-Json -Depth 2"
        )
        if result.return_code != 0 and not result.stdout:
            if "No events were found" in result.stderr:
                return f"No critical/error events found in {log_name} log in the last {hours_back} hours."
            return f"Failed to query event log: {result.stderr}"

        if not result.stdout or result.stdout.strip() == "":
            return f"No critical/error events found in {log_name} log in the last {hours_back} hours."

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Event Log (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        output = f"Event Log Errors — {log_name} (last {hours_back}h):\n\n"
        output += f"Found {len(data)} event(s):\n\n"
        for evt in data:
            msg = evt.get("Message", "No message")
            # Truncate long messages
            if len(msg) > 200:
                msg = msg[:200] + "..."
            output += f"[{evt.get('LevelDisplayName', '?')}] {evt.get('TimeCreated', '?')}\n"
            output += f"  Source: {evt.get('ProviderName', 'Unknown')} (ID: {evt.get('Id', '?')})\n"
            output += f"  {msg}\n\n"
        return output

    @mcp.tool(name="os_sfc_scan", tags={"os"})
    async def sfc_scan() -> str:
        """
        Run System File Checker (sfc /scannow) to detect corrupted
        Windows system files. Requires administrator privileges.
        This command may take several minutes to complete.
        """
        result = await run_command("sfc", ["/scannow"], timeout=600)
        if result.return_code != 0 and "requires" in result.stderr.lower():
            return "SFC requires administrator privileges. Please run the MCP server as administrator."

        output = "System File Checker Results:\n\n"
        output += result.stdout if result.stdout else result.stderr
        if result.timed_out:
            output += "\n\nWARNING: SFC scan timed out. It may still be running in the background."
        return output

    @mcp.tool(name="os_dism_health", tags={"os"})
    async def dism_health(scan_type: str = "CheckHealth") -> str:
        """
        Check Windows image health using DISM.

        Args:
            scan_type: Type of scan — CheckHealth (quick), ScanHealth (thorough),
                       or RestoreHealth (repair). Default: CheckHealth.
        """
        valid = {"CheckHealth", "ScanHealth", "RestoreHealth"}
        if scan_type not in valid:
            return f"Invalid scan type. Choose from: {', '.join(valid)}"

        timeout = 120 if scan_type == "CheckHealth" else 600
        result = await run_command(
            "DISM", ["/Online", "/Cleanup-Image", f"/{scan_type}"],
            timeout=timeout,
        )

        output = f"DISM {scan_type} Results:\n\n"
        output += result.stdout if result.stdout else result.stderr
        if result.timed_out:
            output += f"\n\nWARNING: DISM {scan_type} timed out."
        return output

    @mcp.tool(name="os_windows_updates", tags={"os"})
    async def windows_updates(last_n: int = 20) -> str:
        """
        List recently installed Windows updates.

        Args:
            last_n: Number of recent updates to show (default: 20).
        """
        result = await run_powershell(
            f"Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | "
            f"Select-Object -First {last_n} HotFixID, Description, InstalledBy, InstalledOn | "
            f"ConvertTo-Json"
        )
        if result.return_code != 0:
            return f"Failed to get update history: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Windows Updates (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        output = f"Installed Windows Updates (last {last_n}):\n\n"
        for u in data:
            output += f"{u.get('HotFixID', 'Unknown')}: {u.get('Description', '')}\n"
            output += f"  Installed: {u.get('InstalledOn', 'Unknown')}\n"
            output += f"  By: {u.get('InstalledBy', 'Unknown')}\n\n"
        return output

    @mcp.tool(name="os_driver_status", tags={"os"})
    async def driver_status() -> str:
        """
        List device drivers and identify any problematic devices
        (devices not in OK status).
        """
        result = await run_powershell(
            "$problems = Get-PnpDevice | Where-Object { $_.Status -ne 'OK' } | "
            "Select-Object Status, Class, FriendlyName, InstanceId; "
            "$summary = Get-PnpDevice | Group-Object Status | "
            "Select-Object Name, Count; "
            "@{Problems=$problems; Summary=$summary} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get driver status: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Driver Status (raw):\n{result.stdout}"

        output = "Device/Driver Status:\n\n"

        # Summary
        summary = data.get("Summary", [])
        if not isinstance(summary, list):
            summary = [summary]
        output += "Summary:\n"
        for s in summary:
            output += f"  {s.get('Name', '?')}: {s.get('Count', '?')} devices\n"
        output += "\n"

        # Problematic devices
        problems = data.get("Problems", [])
        if not isinstance(problems, list):
            problems = [problems] if problems else []

        if problems:
            output += f"Problematic Devices ({len(problems)}):\n"
            for d in problems:
                output += f"  [{d.get('Status', '?')}] {d.get('FriendlyName', 'Unknown')}\n"
                output += f"    Class: {d.get('Class', 'Unknown')}\n"
                output += f"    Instance: {d.get('InstanceId', 'Unknown')}\n\n"
        else:
            output += "No problematic devices found.\n"
        return output

    @mcp.tool(name="os_installed_software", tags={"os"})
    async def installed_software(search: str = "") -> str:
        """
        Get a list of installed software with versions.

        Args:
            search: Optional search string to filter by name (case-insensitive).
        """
        filter_clause = ""
        if search:
            filter_clause = f" | Where-Object {{ $_.DisplayName -like '*{search}*' }}"

        result = await run_powershell(
            "$paths = @("
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
            "); "
            "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
            "Where-Object { $_.DisplayName -ne $null }"
            f"{filter_clause} | "
            "Sort-Object DisplayName | "
            "Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, "
            "EstimatedSize | ConvertTo-Json"
        )
        if result.return_code != 0:
            return f"Failed to get installed software: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Installed Software (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        search_note = f" matching '{search}'" if search else ""
        output = f"Installed Software{search_note} ({len(data)} items):\n\n"
        for s in data:
            size_kb = s.get("EstimatedSize")
            size_str = f" ({size_kb / 1024:.1f} MB)" if size_kb else ""
            output += f"{s.get('DisplayName', 'Unknown')} v{s.get('DisplayVersion', '?')}{size_str}\n"
            output += f"  Publisher: {s.get('Publisher', 'Unknown')}\n"
            if s.get("InstallDate"):
                output += f"  Installed: {s['InstallDate']}\n"
            output += "\n"
        return output

    @mcp.tool(name="os_startup_programs", tags={"os"})
    async def startup_programs() -> str:
        """
        List programs configured to run at system startup or user login.
        """
        result = await run_powershell(
            "$startup = Get-CimInstance Win32_StartupCommand | "
            "Select-Object Name, Command, Location, User; "
            "$tasks = Get-ScheduledTask | "
            "Where-Object { $_.Triggers | Where-Object { $_ -is [CimInstance] -and "
            "$_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' } } | "
            "Select-Object TaskName, TaskPath, State, "
            "@{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute }) -join '; '}}; "
            "@{StartupCommands=$startup; LogonTasks=$tasks} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get startup programs: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Startup Programs (raw):\n{result.stdout}"

        output = "Startup Programs:\n\n"

        # Startup commands
        cmds = data.get("StartupCommands", [])
        if not isinstance(cmds, list):
            cmds = [cmds] if cmds else []
        if cmds:
            output += f"Startup Commands ({len(cmds)}):\n"
            for c in cmds:
                output += f"  {c.get('Name', 'Unknown')}\n"
                output += f"    Command: {c.get('Command', '?')}\n"
                output += f"    Location: {c.get('Location', '?')}\n"
                output += f"    User: {c.get('User', '?')}\n\n"

        # Logon scheduled tasks
        tasks = data.get("LogonTasks", [])
        if not isinstance(tasks, list):
            tasks = [tasks] if tasks else []
        if tasks:
            output += f"Logon Scheduled Tasks ({len(tasks)}):\n"
            for t in tasks:
                output += f"  {t.get('TaskName', 'Unknown')}\n"
                output += f"    Path: {t.get('TaskPath', '?')}\n"
                output += f"    State: {t.get('State', '?')}\n"
                output += f"    Actions: {t.get('Actions', '?')}\n\n"

        if not cmds and not tasks:
            output += "No startup programs or logon tasks found.\n"
        return output
