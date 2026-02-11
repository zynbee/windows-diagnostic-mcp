"""Security diagnostic tools for Windows."""

import json
import logging

from fastmcp import FastMCP

from ..utils.command_runner import run_powershell, run_command

logger = logging.getLogger(__name__)


def register_security_tools(mcp: FastMCP):
    """Register all security diagnostic tools with the MCP server."""

    @mcp.tool(name="sec_defender_status", tags={"security"})
    async def defender_status() -> str:
        """
        Get Windows Defender / Microsoft Defender Antivirus status including
        real-time protection, signature freshness, and last scan details.
        """
        result = await run_powershell(
            "try { "
            "  $status = Get-MpComputerStatus -ErrorAction Stop | "
            "    Select-Object AMRunningMode, AMServiceEnabled, "
            "    AntispywareEnabled, AntispywareSignatureLastUpdated, "
            "    AntivirusEnabled, AntivirusSignatureLastUpdated, "
            "    BehaviorMonitorEnabled, IoavProtectionEnabled, "
            "    IsTamperProtected, NISEnabled, "
            "    OnAccessProtectionEnabled, RealTimeProtectionEnabled, "
            "    QuickScanAge, FullScanAge, "
            "    QuickScanStartTime, FullScanStartTime, "
            "    AntivirusSignatureVersion, AntispywareSignatureVersion; "
            "  $status | ConvertTo-Json "
            "} catch { "
            "  Write-Output 'DEFENDER_NOT_AVAILABLE' "
            "}"
        )
        if result.return_code != 0 or "DEFENDER_NOT_AVAILABLE" in result.stdout:
            return "Windows Defender status unavailable. A third-party antivirus may be installed."

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Defender Status (raw):\n{result.stdout}"

        output = "Windows Defender Status:\n\n"

        def yn(val):
            return "Yes" if val else "No"

        output += f"Real-Time Protection: {yn(data.get('RealTimeProtectionEnabled'))}\n"
        output += f"Antivirus Enabled: {yn(data.get('AntivirusEnabled'))}\n"
        output += f"Antispyware Enabled: {yn(data.get('AntispywareEnabled'))}\n"
        output += f"Behavior Monitor: {yn(data.get('BehaviorMonitorEnabled'))}\n"
        output += f"On-Access Protection: {yn(data.get('OnAccessProtectionEnabled'))}\n"
        output += f"Tamper Protection: {yn(data.get('IsTamperProtected'))}\n"
        output += f"Network Protection (NIS): {yn(data.get('NISEnabled'))}\n"
        output += f"IOAV Protection: {yn(data.get('IoavProtectionEnabled'))}\n"
        output += f"Running Mode: {data.get('AMRunningMode', 'Unknown')}\n\n"

        output += "Signatures:\n"
        output += f"  Antivirus Version: {data.get('AntivirusSignatureVersion', '?')}\n"
        output += f"  Antivirus Updated: {data.get('AntivirusSignatureLastUpdated', '?')}\n"
        output += f"  Antispyware Version: {data.get('AntispywareSignatureVersion', '?')}\n"
        output += f"  Antispyware Updated: {data.get('AntispywareSignatureLastUpdated', '?')}\n\n"

        output += "Scans:\n"
        output += f"  Quick Scan Age: {data.get('QuickScanAge', '?')} days\n"
        output += f"  Quick Scan Start: {data.get('QuickScanStartTime', '?')}\n"
        output += f"  Full Scan Age: {data.get('FullScanAge', '?')} days\n"
        output += f"  Full Scan Start: {data.get('FullScanStartTime', '?')}\n"
        return output

    @mcp.tool(name="sec_bitlocker_status", tags={"security"})
    async def bitlocker_status() -> str:
        """
        Get BitLocker drive encryption status for all volumes.
        Requires administrator privileges.
        """
        result = await run_powershell(
            "try { "
            "  $volumes = Get-BitLockerVolume -ErrorAction Stop | "
            "    Select-Object MountPoint, VolumeStatus, ProtectionStatus, "
            "    EncryptionMethod, EncryptionPercentage, LockStatus, "
            "    AutoUnlockEnabled, VolumeType; "
            "  $volumes | ConvertTo-Json "
            "} catch { "
            "  Write-Output 'BITLOCKER_NOT_AVAILABLE' "
            "}"
        )
        if "BITLOCKER_NOT_AVAILABLE" in result.stdout:
            return "BitLocker is not available on this system or requires administrator privileges."

        if result.return_code != 0:
            return f"Failed to get BitLocker status: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"BitLocker Status (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        output = "BitLocker Drive Encryption Status:\n\n"
        for vol in data:
            mount = vol.get("MountPoint", "?")
            protection = vol.get("ProtectionStatus", 0)
            prot_str = {0: "Off", 1: "On", 2: "Unknown"}.get(protection, str(protection))
            vol_status = vol.get("VolumeStatus", 0)
            status_map = {
                0: "FullyDecrypted", 1: "FullyEncrypted",
                2: "EncryptionInProgress", 3: "DecryptionInProgress",
                4: "EncryptionSuspended", 5: "DecryptionSuspended",
            }
            status_str = status_map.get(vol_status, str(vol_status))

            output += f"Volume {mount}:\n"
            output += f"  Protection: {prot_str}\n"
            output += f"  Status: {status_str}\n"
            output += f"  Encryption: {vol.get('EncryptionPercentage', '?')}%\n"
            enc_method = vol.get("EncryptionMethod", 0)
            if enc_method:
                output += f"  Method: {enc_method}\n"
            lock = vol.get("LockStatus", 0)
            output += f"  Locked: {'Yes' if lock == 1 else 'No'}\n"
            output += f"  Type: {vol.get('VolumeType', '?')}\n\n"
        return output

    @mcp.tool(name="sec_local_users", tags={"security"})
    async def local_users() -> str:
        """
        List local user accounts and members of the Administrators group.
        """
        result = await run_powershell(
            "$users = Get-LocalUser | Select-Object Name, Enabled, "
            "LastLogon, PasswordRequired, PasswordExpires, "
            "UserMayChangePassword, Description; "
            "$admins = try { Get-LocalGroupMember -Group 'Administrators' "
            "-ErrorAction Stop | Select-Object Name, ObjectClass, "
            "PrincipalSource } catch { @() }; "
            "@{Users=$users; Admins=$admins} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get user info: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Local Users (raw):\n{result.stdout}"

        output = "Local User Accounts:\n\n"

        users = data.get("Users", [])
        if not isinstance(users, list):
            users = [users] if users else []

        for u in users:
            enabled = "Enabled" if u.get("Enabled") else "Disabled"
            output += f"{u.get('Name', 'Unknown')} [{enabled}]\n"
            if u.get("Description"):
                output += f"  Description: {u['Description']}\n"
            output += f"  Last Logon: {u.get('LastLogon', 'Never')}\n"
            output += f"  Password Required: {'Yes' if u.get('PasswordRequired') else 'No'}\n"
            pw_expires = u.get("PasswordExpires")
            output += f"  Password Expires: {pw_expires if pw_expires else 'Never'}\n\n"

        # Administrators group
        admins = data.get("Admins", [])
        if not isinstance(admins, list):
            admins = [admins] if admins else []
        output += f"Administrators Group ({len(admins)} members):\n"
        for a in admins:
            output += f"  {a.get('Name', 'Unknown')} ({a.get('ObjectClass', '?')}, {a.get('PrincipalSource', '?')})\n"

        return output

    @mcp.tool(name="sec_audit_policy", tags={"security"})
    async def audit_policy() -> str:
        """
        Get the current Windows security audit policy settings.
        Requires administrator privileges.
        """
        result = await run_command("auditpol", ["/get", "/category:*"])
        if result.return_code != 0:
            return f"Failed to get audit policy (admin required): {result.stderr}"

        output = "Windows Audit Policy:\n\n"
        output += result.stdout
        return output

    @mcp.tool(name="sec_open_ports", tags={"security"})
    async def open_ports() -> str:
        """
        List all listening (open) TCP and UDP ports with the processes
        that own them.
        """
        result = await run_powershell(
            "$tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort, "
            "@{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, "
            "OwningProcess; "
            "$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort, "
            "@{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, "
            "OwningProcess; "
            "@{TCP=$tcp; UDP=$udp} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get open ports: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Open Ports (raw):\n{result.stdout}"

        output = "Open Ports:\n\n"

        # TCP listeners
        tcp = data.get("TCP", [])
        if not isinstance(tcp, list):
            tcp = [tcp] if tcp else []
        output += f"TCP Listening ({len(tcp)}):\n"
        output += f"  {'Address':<20} {'Port':<8} {'Process':<25} {'PID':<8}\n"
        output += "  " + "-" * 61 + "\n"
        for c in sorted(tcp, key=lambda x: x.get("LocalPort", 0)):
            pname = c.get("ProcessName", "?") or f"PID:{c.get('OwningProcess', '?')}"
            output += (
                f"  {str(c.get('LocalAddress', '?')):<20} "
                f"{c.get('LocalPort', '?'):<8} "
                f"{pname:<25} "
                f"{c.get('OwningProcess', '?'):<8}\n"
            )

        # UDP endpoints
        udp = data.get("UDP", [])
        if not isinstance(udp, list):
            udp = [udp] if udp else []
        output += f"\nUDP Endpoints ({len(udp)}):\n"
        output += f"  {'Address':<20} {'Port':<8} {'Process':<25} {'PID':<8}\n"
        output += "  " + "-" * 61 + "\n"
        for c in sorted(udp, key=lambda x: x.get("LocalPort", 0)):
            pname = c.get("ProcessName", "?") or f"PID:{c.get('OwningProcess', '?')}"
            output += (
                f"  {str(c.get('LocalAddress', '?')):<20} "
                f"{c.get('LocalPort', '?'):<8} "
                f"{pname:<25} "
                f"{c.get('OwningProcess', '?'):<8}\n"
            )

        return output
