"""Performance diagnostic tools for Windows."""

import json
import logging

from fastmcp import FastMCP

from ..utils.command_runner import run_powershell

logger = logging.getLogger(__name__)


def register_performance_tools(mcp: FastMCP):
    """Register all performance diagnostic tools with the MCP server."""

    @mcp.tool(name="perf_system_snapshot", tags={"performance"})
    async def system_snapshot() -> str:
        """
        Get a real-time snapshot of system resource utilization:
        CPU usage, memory usage, and disk activity.
        """
        result = await run_powershell(
            "$counters = Get-Counter -Counter "
            "@("
            "'\\Processor(_Total)\\% Processor Time',"
            "'\\Memory\\Available MBytes',"
            "'\\Memory\\% Committed Bytes In Use',"
            "'\\PhysicalDisk(_Total)\\% Disk Time',"
            "'\\PhysicalDisk(_Total)\\Disk Read Bytes/sec',"
            "'\\PhysicalDisk(_Total)\\Disk Write Bytes/sec',"
            "'\\PhysicalDisk(_Total)\\Current Disk Queue Length',"
            "'\\Network Interface(*)\\Bytes Total/sec'"
            ") -ErrorAction SilentlyContinue; "
            "$os = Get-CimInstance Win32_OperatingSystem | "
            "Select-Object TotalVisibleMemorySize, FreePhysicalMemory; "
            "$samples = $counters.CounterSamples | "
            "Select-Object Path, CookedValue; "
            "@{Counters=$samples; OS=$os} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get system snapshot: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"System Snapshot (raw):\n{result.stdout}"

        output = "System Resource Snapshot:\n\n"

        # Parse counters
        counters = data.get("Counters", [])
        if not isinstance(counters, list):
            counters = [counters]

        for c in counters:
            path = c.get("Path", "")
            val = c.get("CookedValue", 0)
            name = path.split("\\")[-1] if path else "Unknown"
            parent = path.split("\\")[-2] if path and path.count("\\") >= 2 else ""

            if "% processor time" in path.lower() and "_total" in path.lower():
                output += f"CPU Usage: {val:.1f}%\n"
            elif "available mbytes" in path.lower():
                output += f"Available Memory: {val:.0f} MB\n"
            elif "% committed bytes" in path.lower():
                output += f"Memory Committed: {val:.1f}%\n"
            elif "% disk time" in path.lower() and "_total" in path.lower():
                output += f"Disk Activity: {val:.1f}%\n"
            elif "disk read bytes" in path.lower() and "_total" in path.lower():
                output += f"Disk Read Rate: {val / (1024*1024):.1f} MB/s\n"
            elif "disk write bytes" in path.lower() and "_total" in path.lower():
                output += f"Disk Write Rate: {val / (1024*1024):.1f} MB/s\n"
            elif "disk queue" in path.lower():
                output += f"Disk Queue Length: {val:.1f}\n"
            elif "bytes total/sec" in path.lower() and val > 0:
                output += f"Network ({parent}): {val / (1024*1024):.2f} MB/s\n"

        # Memory details
        os_info = data.get("OS", {})
        total_kb = os_info.get("TotalVisibleMemorySize", 0)
        free_kb = os_info.get("FreePhysicalMemory", 0)
        if total_kb:
            total_gb = total_kb / (1024 * 1024)
            used_gb = (total_kb - free_kb) / (1024 * 1024)
            output += f"\nMemory: {used_gb:.1f} / {total_gb:.1f} GB used\n"

        return output

    @mcp.tool(name="perf_top_processes", tags={"performance"})
    async def top_processes(top_n: int = 20, sort_by: str = "CPU") -> str:
        """
        Get the top processes by CPU or memory usage.

        Args:
            top_n: Number of top processes to return (default: 20).
            sort_by: Sort by CPU or Memory (default: CPU).
        """
        sort_field = "CPU" if sort_by.upper() == "CPU" else "WorkingSet64"

        result = await run_powershell(
            f"Get-Process | Where-Object {{ $_.CPU -gt 0 }} | "
            f"Sort-Object {sort_field} -Descending | "
            f"Select-Object -First {top_n} "
            f"Id, ProcessName, CPU, "
            f"@{{N='MemoryMB';E={{[math]::Round($_.WorkingSet64/1MB,1)}}}}, "
            f"@{{N='Threads';E={{$_.Threads.Count}}}}, "
            f"Handles, StartTime | "
            f"ConvertTo-Json"
        )
        if result.return_code != 0:
            return f"Failed to get processes: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Top Processes (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        output = f"Top {len(data)} Processes (by {sort_by}):\n\n"
        output += f"{'PID':<8} {'Name':<30} {'CPU (s)':<12} {'Memory':<12} {'Threads':<10} {'Handles':<10}\n"
        output += "-" * 82 + "\n"

        for p in data:
            cpu_s = p.get("CPU", 0)
            cpu_str = f"{cpu_s:.1f}" if cpu_s else "0.0"
            mem_str = f"{p.get('MemoryMB', 0)} MB"
            output += (
                f"{p.get('Id', '?'):<8} "
                f"{str(p.get('ProcessName', 'Unknown'))[:29]:<30} "
                f"{cpu_str:<12} "
                f"{mem_str:<12} "
                f"{p.get('Threads', '?'):<10} "
                f"{p.get('Handles', '?'):<10}\n"
            )
        return output

    @mcp.tool(name="perf_memory_analysis", tags={"performance"})
    async def memory_analysis() -> str:
        """
        Detailed memory pressure analysis including committed bytes,
        available memory, page faults, cache, and pool sizes.
        """
        result = await run_powershell(
            "$counters = Get-Counter -Counter "
            "@("
            "'\\Memory\\Available MBytes',"
            "'\\Memory\\% Committed Bytes In Use',"
            "'\\Memory\\Committed Bytes',"
            "'\\Memory\\Cache Bytes',"
            "'\\Memory\\Pool Paged Bytes',"
            "'\\Memory\\Pool Nonpaged Bytes',"
            "'\\Memory\\Pages/sec',"
            "'\\Memory\\Page Faults/sec',"
            "'\\Paging File(_Total)\\% Usage'"
            ") -ErrorAction SilentlyContinue; "
            "$os = Get-CimInstance Win32_OperatingSystem | "
            "Select-Object TotalVisibleMemorySize, FreePhysicalMemory, "
            "TotalVirtualMemorySize, FreeVirtualMemory; "
            "$samples = $counters.CounterSamples | "
            "Select-Object Path, CookedValue; "
            "@{Counters=$samples; OS=$os} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get memory analysis: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Memory Analysis (raw):\n{result.stdout}"

        output = "Memory Analysis:\n\n"

        os_info = data.get("OS", {})
        total_kb = os_info.get("TotalVisibleMemorySize", 0)
        free_kb = os_info.get("FreePhysicalMemory", 0)
        vtotal_kb = os_info.get("TotalVirtualMemorySize", 0)
        vfree_kb = os_info.get("FreeVirtualMemory", 0)

        if total_kb:
            output += f"Physical Memory: {(total_kb - free_kb) / (1024*1024):.1f} / {total_kb / (1024*1024):.1f} GB used\n"
        if vtotal_kb:
            output += f"Virtual Memory: {(vtotal_kb - vfree_kb) / (1024*1024):.1f} / {vtotal_kb / (1024*1024):.1f} GB used\n"

        output += "\nPerformance Counters:\n"
        counters = data.get("Counters", [])
        if not isinstance(counters, list):
            counters = [counters]

        for c in counters:
            path = c.get("Path", "").lower()
            val = c.get("CookedValue", 0)

            if "available mbytes" in path:
                output += f"  Available: {val:.0f} MB\n"
            elif "% committed bytes" in path:
                output += f"  Committed %: {val:.1f}%\n"
            elif "committed bytes" in path and "%" not in path:
                output += f"  Committed: {val / (1024**3):.2f} GB\n"
            elif "cache bytes" in path:
                output += f"  Cache: {val / (1024**2):.0f} MB\n"
            elif "pool paged" in path:
                output += f"  Paged Pool: {val / (1024**2):.0f} MB\n"
            elif "pool nonpaged" in path:
                output += f"  Non-Paged Pool: {val / (1024**2):.0f} MB\n"
            elif "pages/sec" in path:
                output += f"  Pages/sec: {val:.0f}\n"
            elif "page faults/sec" in path:
                output += f"  Page Faults/sec: {val:.0f}\n"
            elif "paging file" in path:
                output += f"  Page File Usage: {val:.1f}%\n"

        return output

    @mcp.tool(name="perf_disk_io", tags={"performance"})
    async def disk_io() -> str:
        """
        Get per-disk I/O performance metrics including read/write rates,
        queue depths, and latency.
        """
        result = await run_powershell(
            "$counters = Get-Counter -Counter "
            "@("
            "'\\PhysicalDisk(*)\\Disk Reads/sec',"
            "'\\PhysicalDisk(*)\\Disk Writes/sec',"
            "'\\PhysicalDisk(*)\\Disk Read Bytes/sec',"
            "'\\PhysicalDisk(*)\\Disk Write Bytes/sec',"
            "'\\PhysicalDisk(*)\\Avg. Disk sec/Read',"
            "'\\PhysicalDisk(*)\\Avg. Disk sec/Write',"
            "'\\PhysicalDisk(*)\\Current Disk Queue Length',"
            "'\\PhysicalDisk(*)\\% Disk Time'"
            ") -ErrorAction SilentlyContinue; "
            "$counters.CounterSamples | Where-Object { $_.InstanceName -ne '_total' } | "
            "Select-Object InstanceName, Path, CookedValue | "
            "ConvertTo-Json -Depth 2"
        )
        if result.return_code != 0:
            return f"Failed to get disk I/O: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Disk I/O (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        # Group by disk instance
        disks: dict[str, dict] = {}
        for c in data:
            instance = c.get("InstanceName", "unknown")
            path = c.get("Path", "").lower()
            val = c.get("CookedValue", 0)
            disks.setdefault(instance, {})

            if "reads/sec" in path:
                disks[instance]["reads_sec"] = val
            elif "writes/sec" in path:
                disks[instance]["writes_sec"] = val
            elif "read bytes/sec" in path:
                disks[instance]["read_bytes_sec"] = val
            elif "write bytes/sec" in path:
                disks[instance]["write_bytes_sec"] = val
            elif "sec/read" in path:
                disks[instance]["avg_read_latency"] = val
            elif "sec/write" in path:
                disks[instance]["avg_write_latency"] = val
            elif "queue length" in path:
                disks[instance]["queue_length"] = val
            elif "% disk time" in path:
                disks[instance]["disk_pct"] = val

        output = "Disk I/O Performance:\n\n"
        for name, metrics in sorted(disks.items()):
            output += f"Disk: {name}\n"
            output += f"  Active: {metrics.get('disk_pct', 0):.1f}%\n"
            output += f"  Reads: {metrics.get('reads_sec', 0):.1f}/s ({metrics.get('read_bytes_sec', 0) / (1024*1024):.2f} MB/s)\n"
            output += f"  Writes: {metrics.get('writes_sec', 0):.1f}/s ({metrics.get('write_bytes_sec', 0) / (1024*1024):.2f} MB/s)\n"
            read_lat = metrics.get('avg_read_latency', 0)
            write_lat = metrics.get('avg_write_latency', 0)
            output += f"  Avg Read Latency: {read_lat * 1000:.2f} ms\n"
            output += f"  Avg Write Latency: {write_lat * 1000:.2f} ms\n"
            output += f"  Queue Length: {metrics.get('queue_length', 0):.1f}\n\n"
        return output

    @mcp.tool(name="perf_boot_analysis", tags={"performance"})
    async def boot_analysis() -> str:
        """
        Analyze boot time, last boot timestamp, and recent boot/shutdown
        event history from the System event log.
        """
        result = await run_powershell(
            "$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime; "
            "$uptime = (Get-Date) - $bootTime; "
            "$events = Get-WinEvent -FilterHashtable @{"
            "LogName='System'; Id=6005,6006,6008,6009,6013"
            "} -MaxEvents 30 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Id, Message; "
            "@{BootTime=$bootTime.ToString('o'); "
            "UptimeDays=$uptime.Days; UptimeHours=$uptime.Hours; "
            "UptimeMinutes=$uptime.Minutes; "
            "Events=@($events)} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get boot analysis: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Boot Analysis (raw):\n{result.stdout}"

        output = "Boot Analysis:\n\n"
        output += f"Last Boot: {data.get('BootTime', 'Unknown')}\n"
        output += f"Uptime: {data.get('UptimeDays', 0)}d {data.get('UptimeHours', 0)}h {data.get('UptimeMinutes', 0)}m\n\n"

        events = data.get("Events", [])
        if not isinstance(events, list):
            events = [events] if events else []

        event_names = {
            6005: "Event Log Started (boot)",
            6006: "Event Log Stopped (clean shutdown)",
            6008: "Unexpected Shutdown",
            6009: "OS Info at Boot",
            6013: "System Uptime",
        }

        if events:
            output += "Recent Boot/Shutdown Events:\n"
            for e in events:
                eid = e.get("Id", 0)
                desc = event_names.get(eid, f"Event {eid}")
                msg = e.get("Message", "")
                if len(msg) > 150:
                    msg = msg[:150] + "..."
                output += f"  [{e.get('TimeCreated', '?')}] {desc}\n"
                if msg:
                    output += f"    {msg}\n"
                output += "\n"
        return output

    @mcp.tool(name="perf_service_health", tags={"performance"})
    async def service_health() -> str:
        """
        Identify Windows services set to auto-start that are currently
        stopped, which may indicate failures or issues.
        """
        result = await run_powershell(
            "$stopped = Get-Service | Where-Object { "
            "$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | "
            "Select-Object Name, DisplayName, Status, StartType; "
            "$running = (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count; "
            "$total = (Get-Service).Count; "
            "@{StoppedAutoStart=$stopped; RunningCount=$running; TotalCount=$total} | "
            "ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get service health: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Service Health (raw):\n{result.stdout}"

        output = "Service Health:\n\n"
        output += f"Total Services: {data.get('TotalCount', '?')}\n"
        output += f"Running: {data.get('RunningCount', '?')}\n\n"

        stopped = data.get("StoppedAutoStart", [])
        if not isinstance(stopped, list):
            stopped = [stopped] if stopped else []

        if stopped:
            output += f"Auto-Start Services NOT Running ({len(stopped)}):\n"
            for s in stopped:
                output += f"  {s.get('DisplayName', 'Unknown')} ({s.get('Name', '?')})\n"
                output += f"    Status: {s.get('Status', '?')}\n\n"
        else:
            output += "All auto-start services are running normally.\n"
        return output
