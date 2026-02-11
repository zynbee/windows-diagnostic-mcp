"""Hardware diagnostic tools for Windows."""

import json
import logging
import tempfile
import os
from typing import Optional

from fastmcp import FastMCP

from ..utils.command_runner import run_powershell, run_command
from ..utils.tool_checker import AVAILABLE_TOOLS

logger = logging.getLogger(__name__)


def register_hardware_tools(mcp: FastMCP):
    """Register all hardware diagnostic tools with the MCP server."""

    @mcp.tool(name="hw_disk_health", tags={"hardware"})
    async def disk_health(drive_index: int = 0) -> str:
        """
        Get SMART health data for a physical drive.

        Returns temperature, reallocated sectors, power-on hours, overall
        health status, and other SMART attributes.

        Args:
            drive_index: Physical drive number (default: 0). Use 0 for the
                         first drive, 1 for the second, etc.
        """
        if AVAILABLE_TOOLS["smartctl"]:
            result = await run_command(
                "smartctl", ["-a", f"/dev/pd{drive_index}", "--json"]
            )
            if result.return_code == 0 or result.stdout:
                try:
                    data = json.loads(result.stdout)
                    output = f"Disk Health (Drive {drive_index}) — via smartctl\n\n"
                    # Device info
                    dev = data.get("device", {})
                    model = data.get("model_name", "Unknown")
                    serial = data.get("serial_number", "Unknown")
                    fw = data.get("firmware_version", "Unknown")
                    output += f"Model: {model}\n"
                    output += f"Serial: {serial}\n"
                    output += f"Firmware: {fw}\n"
                    # Health
                    health = data.get("smart_status", {}).get("passed")
                    if health is not None:
                        output += f"SMART Health: {'PASSED' if health else 'FAILED'}\n"
                    # Temperature
                    temp = data.get("temperature", {}).get("current")
                    if temp is not None:
                        output += f"Temperature: {temp}°C\n"
                    # Power-on hours
                    poh = data.get("power_on_time", {}).get("hours")
                    if poh is not None:
                        output += f"Power-On Hours: {poh}\n"
                    # Power cycle count
                    pcc = data.get("power_cycle_count")
                    if pcc is not None:
                        output += f"Power Cycle Count: {pcc}\n"
                    # SMART attributes table
                    attrs = data.get("ata_smart_attributes", {}).get("table", [])
                    if attrs:
                        output += "\nSMART Attributes:\n"
                        for attr in attrs:
                            name = attr.get("name", "Unknown")
                            value = attr.get("value", "")
                            worst = attr.get("worst", "")
                            raw_val = attr.get("raw", {}).get("string", "")
                            output += f"  {name}: value={value}, worst={worst}, raw={raw_val}\n"
                    return output
                except json.JSONDecodeError:
                    pass  # Fall through to fallback

        # Fallback: PowerShell
        result = await run_powershell(
            "$disks = Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, "
            "MediaType, HealthStatus, OperationalStatus, Size; "
            "$reliability = Get-PhysicalDisk | Get-StorageReliabilityCounter | "
            "Select-Object DeviceId, Temperature, Wear, ReadErrorsTotal, "
            "WriteErrorsTotal, PowerOnHours; "
            "@{Disks=$disks; Reliability=$reliability} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get disk health: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Disk Health (raw output):\n{result.stdout}"

        output = "Disk Health — via PowerShell (install smartmontools for detailed SMART data)\n\n"
        disks = data.get("Disks", [])
        if not isinstance(disks, list):
            disks = [disks]
        for d in disks:
            size_gb = int(d.get("Size", 0)) / (1024**3)
            output += f"Drive {d.get('DeviceId', '?')}: {d.get('FriendlyName', 'Unknown')}\n"
            output += f"  Type: {d.get('MediaType', 'Unknown')}\n"
            output += f"  Health: {d.get('HealthStatus', 'Unknown')}\n"
            output += f"  Status: {d.get('OperationalStatus', 'Unknown')}\n"
            output += f"  Size: {size_gb:.1f} GB\n"

        reliability = data.get("Reliability", [])
        if not isinstance(reliability, list):
            reliability = [reliability]
        for r in reliability:
            if r:
                output += f"\n  Drive {r.get('DeviceId', '?')} Reliability:\n"
                if r.get("Temperature") is not None:
                    output += f"    Temperature: {r['Temperature']}°C\n"
                if r.get("Wear") is not None:
                    output += f"    Wear: {r['Wear']}%\n"
                if r.get("PowerOnHours") is not None:
                    output += f"    Power-On Hours: {r['PowerOnHours']}\n"
                if r.get("ReadErrorsTotal") is not None:
                    output += f"    Read Errors: {r['ReadErrorsTotal']}\n"
                if r.get("WriteErrorsTotal") is not None:
                    output += f"    Write Errors: {r['WriteErrorsTotal']}\n"
        return output

    @mcp.tool(name="hw_disk_benchmark", tags={"hardware"})
    async def disk_benchmark(
        drive_letter: str = "C",
        duration_seconds: int = 10,
    ) -> str:
        """
        Run a read/write performance benchmark on a drive.

        Args:
            drive_letter: Drive letter to benchmark (default: C).
            duration_seconds: Test duration in seconds (default: 10).
        """
        test_dir = f"{drive_letter}:\\__diskbench_tmp"
        test_file = f"{test_dir}\\testfile.dat"

        if AVAILABLE_TOOLS["diskspd"]:
            # diskspd: 4K random 70% read / 30% write, 1 thread, queue depth 4
            result = await run_command(
                "diskspd",
                [
                    f"-d{duration_seconds}",
                    "-b4K", "-o4", "-t1", "-r",
                    "-w30", "-L", "-Sh",
                    "-c64M",
                    test_file,
                ],
                timeout=duration_seconds + 30,
            )
            # Clean up
            await run_powershell(f"Remove-Item -Path '{test_dir}' -Recurse -Force -ErrorAction SilentlyContinue")
            if result.return_code == 0:
                return f"Disk Benchmark ({drive_letter}:) — via diskspd\n\n{result.stdout}"
            return f"diskspd failed (exit {result.return_code}): {result.stderr}\n{result.stdout}"

        # Fallback: winsat
        result = await run_command(
            "winsat", ["disk", "-drive", drive_letter],
            timeout=duration_seconds + 60,
        )
        if result.return_code == 0:
            return f"Disk Benchmark ({drive_letter}:) — via Windows System Assessment Tool\n\n{result.stdout}"
        return f"winsat failed: {result.stderr}"

    @mcp.tool(name="hw_cpu_info", tags={"hardware"})
    async def cpu_info() -> str:
        """
        Get CPU information including model, cores, clock speed, cache,
        and current utilization.
        """
        result = await run_powershell(
            "Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, "
            "NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, "
            "CurrentClockSpeed, L2CacheSize, L3CacheSize, LoadPercentage, "
            "SocketDesignation, Architecture | ConvertTo-Json"
        )
        if result.return_code != 0:
            return f"Failed to get CPU info: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"CPU Info (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        output = "CPU Information:\n\n"
        for i, cpu in enumerate(data):
            output += f"Processor {i}:\n"
            output += f"  Name: {cpu.get('Name', 'Unknown')}\n"
            output += f"  Manufacturer: {cpu.get('Manufacturer', 'Unknown')}\n"
            output += f"  Cores: {cpu.get('NumberOfCores', '?')}\n"
            output += f"  Logical Processors: {cpu.get('NumberOfLogicalProcessors', '?')}\n"
            output += f"  Max Clock: {cpu.get('MaxClockSpeed', '?')} MHz\n"
            output += f"  Current Clock: {cpu.get('CurrentClockSpeed', '?')} MHz\n"
            l2 = cpu.get('L2CacheSize')
            l3 = cpu.get('L3CacheSize')
            if l2:
                output += f"  L2 Cache: {l2} KB\n"
            if l3:
                output += f"  L3 Cache: {l3} KB\n"
            output += f"  Current Load: {cpu.get('LoadPercentage', '?')}%\n"
            output += f"  Socket: {cpu.get('SocketDesignation', 'Unknown')}\n\n"
        return output

    @mcp.tool(name="hw_memory_info", tags={"hardware"})
    async def memory_info() -> str:
        """
        Get physical RAM details (modules, capacity, speed, type) and
        current memory usage statistics.
        """
        result = await run_powershell(
            "$modules = Get-CimInstance Win32_PhysicalMemory | "
            "Select-Object BankLabel, Capacity, Speed, MemoryType, "
            "Manufacturer, PartNumber, FormFactor; "
            "$os = Get-CimInstance Win32_OperatingSystem | "
            "Select-Object TotalVisibleMemorySize, FreePhysicalMemory, "
            "TotalVirtualMemorySize, FreeVirtualMemory; "
            "@{Modules=$modules; Usage=$os} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get memory info: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Memory Info (raw):\n{result.stdout}"

        output = "Memory Information:\n\n"

        # Usage
        usage = data.get("Usage", {})
        if usage:
            total_kb = usage.get("TotalVisibleMemorySize", 0)
            free_kb = usage.get("FreePhysicalMemory", 0)
            total_gb = total_kb / (1024 * 1024) if total_kb else 0
            free_gb = free_kb / (1024 * 1024) if free_kb else 0
            used_gb = total_gb - free_gb
            pct = (used_gb / total_gb * 100) if total_gb > 0 else 0
            output += f"Usage: {used_gb:.1f} GB / {total_gb:.1f} GB ({pct:.0f}% used)\n"
            output += f"Free: {free_gb:.1f} GB\n\n"

        # Modules
        modules = data.get("Modules", [])
        if not isinstance(modules, list):
            modules = [modules]
        output += f"Physical Modules ({len(modules)}):\n"
        for m in modules:
            cap_gb = int(m.get("Capacity", 0)) / (1024**3)
            output += f"  {m.get('BankLabel', 'Unknown')}:\n"
            output += f"    Capacity: {cap_gb:.0f} GB\n"
            output += f"    Speed: {m.get('Speed', '?')} MHz\n"
            output += f"    Manufacturer: {m.get('Manufacturer', 'Unknown')}\n"
            output += f"    Part Number: {m.get('PartNumber', 'Unknown').strip()}\n"
        return output

    @mcp.tool(name="hw_gpu_info", tags={"hardware"})
    async def gpu_info() -> str:
        """
        Get GPU information including model, driver version, VRAM,
        and (if NVIDIA) temperature and utilization.
        """
        output = "GPU Information:\n\n"

        # Try nvidia-smi for detailed NVIDIA info
        if AVAILABLE_TOOLS["nvidia_smi"]:
            result = await run_command(
                "nvidia-smi",
                [
                    "--query-gpu=name,driver_version,memory.total,memory.used,"
                    "memory.free,temperature.gpu,utilization.gpu,utilization.memory,"
                    "fan.speed,power.draw",
                    "--format=csv,noheader,nounits",
                ],
            )
            if result.return_code == 0 and result.stdout:
                output += "NVIDIA GPU (via nvidia-smi):\n"
                for line in result.stdout.strip().split("\n"):
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 10:
                        output += f"  Name: {parts[0]}\n"
                        output += f"  Driver: {parts[1]}\n"
                        output += f"  VRAM Total: {parts[2]} MiB\n"
                        output += f"  VRAM Used: {parts[3]} MiB\n"
                        output += f"  VRAM Free: {parts[4]} MiB\n"
                        output += f"  Temperature: {parts[5]}°C\n"
                        output += f"  GPU Utilization: {parts[6]}%\n"
                        output += f"  Memory Utilization: {parts[7]}%\n"
                        output += f"  Fan Speed: {parts[8]}%\n"
                        output += f"  Power Draw: {parts[9]} W\n\n"
                return output

        # Fallback: WMI
        result = await run_powershell(
            "Get-CimInstance Win32_VideoController | Select-Object Name, "
            "DriverVersion, AdapterRAM, VideoProcessor, CurrentRefreshRate, "
            "VideoModeDescription, Status | ConvertTo-Json"
        )
        if result.return_code != 0:
            return f"Failed to get GPU info: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"GPU Info (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        for gpu in data:
            vram_mb = int(gpu.get("AdapterRAM", 0)) / (1024**2)
            output += f"  Name: {gpu.get('Name', 'Unknown')}\n"
            output += f"  Driver: {gpu.get('DriverVersion', 'Unknown')}\n"
            output += f"  VRAM: {vram_mb:.0f} MB\n"
            output += f"  Video Mode: {gpu.get('VideoModeDescription', 'Unknown')}\n"
            output += f"  Refresh Rate: {gpu.get('CurrentRefreshRate', '?')} Hz\n"
            output += f"  Status: {gpu.get('Status', 'Unknown')}\n\n"

        if not AVAILABLE_TOOLS["nvidia_smi"]:
            output += "(Install nvidia-smi for temperature and utilization data on NVIDIA GPUs)\n"
        return output

    @mcp.tool(name="hw_battery_health", tags={"hardware"})
    async def battery_health() -> str:
        """
        Get battery health report including cycle count, design capacity
        vs current full charge capacity, and wear percentage.
        Only applicable on laptops/devices with batteries.
        """
        report_path = os.path.join(tempfile.gettempdir(), "battery-report.xml")

        result = await run_command(
            "powercfg", ["/batteryreport", "/output", report_path, "/xml"]
        )
        if result.return_code != 0:
            # May not have a battery
            if "no battery" in result.stderr.lower() or "no battery" in result.stdout.lower():
                return "No battery detected on this system."
            return f"Failed to generate battery report: {result.stderr}"

        # Parse the XML with PowerShell
        parse_script = f"""
[xml]$xml = Get-Content '{report_path}'
$batteries = $xml.BatteryReport.Batteries.Battery
$recent = $xml.BatteryReport.RecentUsage.Usage | Select-Object -Last 10
$result = @{{
    SystemInfo = @{{
        ComputerName = $xml.BatteryReport.SystemInformation.ComputerName
        BIOS = $xml.BatteryReport.SystemInformation.BIOS
    }}
    Batteries = @($batteries | ForEach-Object {{
        @{{
            Id = $_.Id
            Manufacturer = $_.Manufacturer
            SerialNumber = $_.SerialNumber
            Chemistry = $_.Chemistry
            DesignCapacity = $_.DesignCapacity
            FullChargeCapacity = $_.FullChargeCapacity
            CycleCount = $_.CycleCount
        }}
    }})
}}
$result | ConvertTo-Json -Depth 4
"""
        parse_result = await run_powershell(parse_script)

        # Clean up report file
        try:
            os.unlink(report_path)
        except OSError:
            pass

        if parse_result.return_code != 0:
            return f"Failed to parse battery report: {parse_result.stderr}"

        try:
            data = json.loads(parse_result.stdout)
        except json.JSONDecodeError:
            return f"Battery Report (raw):\n{parse_result.stdout}"

        output = "Battery Health Report:\n\n"
        sys_info = data.get("SystemInfo", {})
        output += f"Computer: {sys_info.get('ComputerName', 'Unknown')}\n\n"

        batteries = data.get("Batteries", [])
        if not isinstance(batteries, list):
            batteries = [batteries]

        for b in batteries:
            design = int(b.get("DesignCapacity", 0) or 0)
            full = int(b.get("FullChargeCapacity", 0) or 0)
            wear = ((design - full) / design * 100) if design > 0 else 0

            output += f"Battery: {b.get('Manufacturer', 'Unknown')}\n"
            output += f"  Serial: {b.get('SerialNumber', 'Unknown')}\n"
            output += f"  Chemistry: {b.get('Chemistry', 'Unknown')}\n"
            output += f"  Design Capacity: {design} mWh\n"
            output += f"  Full Charge Capacity: {full} mWh\n"
            output += f"  Wear: {wear:.1f}%\n"
            output += f"  Cycle Count: {b.get('CycleCount', 'Unknown')}\n\n"

        return output

    @mcp.tool(name="hw_sensor_readings", tags={"hardware"})
    async def sensor_readings() -> str:
        """
        Get hardware sensor readings including CPU/disk temperatures.

        Uses LibreHardwareMonitor WMI provider if available, otherwise
        falls back to ACPI thermal zone data (limited).
        """
        # Try LibreHardwareMonitor WMI namespace first
        lhm_result = await run_powershell(
            "try { "
            "  $sensors = Get-CimInstance -Namespace root/LibreHardwareMonitor "
            "    -ClassName Sensor -ErrorAction Stop | "
            "    Select-Object Name, SensorType, Value, Parent, Identifier; "
            "  $sensors | ConvertTo-Json -Depth 2 "
            "} catch { Write-Output 'LHM_NOT_AVAILABLE' }"
        )

        if lhm_result.return_code == 0 and "LHM_NOT_AVAILABLE" not in lhm_result.stdout:
            try:
                data = json.loads(lhm_result.stdout)
                if not isinstance(data, list):
                    data = [data]

                output = "Sensor Readings — via LibreHardwareMonitor:\n\n"
                # Group by sensor type
                by_type: dict[str, list] = {}
                for s in data:
                    stype = s.get("SensorType", "Other")
                    by_type.setdefault(stype, []).append(s)

                for stype in ["Temperature", "Fan", "Voltage", "Power", "Clock", "Load"]:
                    sensors = by_type.get(stype, [])
                    if sensors:
                        output += f"{stype}:\n"
                        for s in sensors:
                            val = s.get("Value", "?")
                            unit = {"Temperature": "°C", "Fan": " RPM", "Voltage": " V",
                                    "Power": " W", "Clock": " MHz", "Load": "%"}.get(stype, "")
                            if isinstance(val, float):
                                output += f"  {s.get('Name', 'Unknown')}: {val:.1f}{unit}\n"
                            else:
                                output += f"  {s.get('Name', 'Unknown')}: {val}{unit}\n"
                        output += "\n"
                return output
            except json.JSONDecodeError:
                pass

        # Fallback: ACPI thermal zones
        result = await run_powershell(
            "try { "
            "  $temps = Get-CimInstance MSAcpi_ThermalZoneTemperature "
            "    -Namespace root/wmi -ErrorAction Stop | "
            "    Select-Object InstanceName, CurrentTemperature; "
            "  $temps | ConvertTo-Json "
            "} catch { Write-Output 'ACPI_NOT_AVAILABLE' }"
        )

        if result.return_code == 0 and "ACPI_NOT_AVAILABLE" not in result.stdout:
            try:
                data = json.loads(result.stdout)
                if not isinstance(data, list):
                    data = [data]
                output = "Sensor Readings — via ACPI Thermal Zones (limited):\n\n"
                for tz in data:
                    # ACPI temps are in tenths of kelvin
                    raw = tz.get("CurrentTemperature", 0)
                    celsius = (raw / 10.0) - 273.15 if raw else 0
                    output += f"  {tz.get('InstanceName', 'Unknown')}: {celsius:.1f}°C\n"
                output += "\n(Install LibreHardwareMonitor for comprehensive sensor data)\n"
                return output
            except json.JSONDecodeError:
                pass

        return (
            "No sensor data available.\n\n"
            "To get comprehensive sensor readings, install and run LibreHardwareMonitor:\n"
            "  https://github.com/LibreHardwareMonitor/LibreHardwareMonitor\n"
            "It exposes a WMI provider that this tool reads from."
        )
