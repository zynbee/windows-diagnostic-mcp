"""Network diagnostic tools for Windows."""

import json
import logging

from fastmcp import FastMCP

from ..utils.command_runner import run_powershell, run_command
from ..utils.tool_checker import AVAILABLE_TOOLS

logger = logging.getLogger(__name__)


def register_network_tools(mcp: FastMCP):
    """Register all network diagnostic tools with the MCP server."""

    @mcp.tool(name="net_connectivity_test", tags={"network"})
    async def connectivity_test(target: str = "8.8.8.8") -> str:
        """
        Test network connectivity with ping, DNS resolution, and TCP port tests.

        Args:
            target: Hostname or IP to test connectivity to (default: 8.8.8.8).
        """
        result = await run_powershell(
            f"$ping = Test-Connection -ComputerName '{target}' -Count 4 "
            f"-ErrorAction SilentlyContinue | "
            f"Select-Object Address, Latency, Status; "
            f"$dns = try {{ Resolve-DnsName 'www.google.com' -ErrorAction Stop | "
            f"Select-Object -First 3 Name, Type, IPAddress }} catch {{ $null }}; "
            f"$tcp443 = Test-NetConnection -ComputerName '{target}' -Port 443 "
            f"-WarningAction SilentlyContinue | "
            f"Select-Object ComputerName, RemotePort, TcpTestSucceeded, "
            f"PingSucceeded, InterfaceAlias; "
            f"@{{Ping=$ping; DNS=$dns; TCP=$tcp443}} | ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Connectivity test failed: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Connectivity Test (raw):\n{result.stdout}"

        output = f"Connectivity Test ({target}):\n\n"

        # Ping results
        pings = data.get("Ping", [])
        if not isinstance(pings, list):
            pings = [pings] if pings else []
        if pings:
            latencies = [p.get("Latency", 0) for p in pings if p.get("Latency") is not None]
            if latencies:
                avg_lat = sum(latencies) / len(latencies)
                output += f"Ping: {len(latencies)}/{len(pings)} replies, avg latency {avg_lat:.0f} ms\n"
            else:
                output += "Ping: No replies received\n"
        else:
            output += "Ping: Failed (no response)\n"

        # DNS resolution
        dns = data.get("DNS", [])
        if dns:
            if not isinstance(dns, list):
                dns = [dns]
            output += f"DNS Resolution (google.com): OK\n"
            for d in dns:
                output += f"  {d.get('Name', '?')} -> {d.get('IPAddress', 'N/A')} ({d.get('Type', '?')})\n"
        else:
            output += "DNS Resolution: FAILED\n"

        # TCP test
        tcp = data.get("TCP", {})
        if tcp:
            output += f"\nTCP {target}:443: {'SUCCESS' if tcp.get('TcpTestSucceeded') else 'FAILED'}\n"
            output += f"  Interface: {tcp.get('InterfaceAlias', 'Unknown')}\n"

        return output

    @mcp.tool(name="net_dns_diagnostics", tags={"network"})
    async def dns_diagnostics(domain: str = "www.google.com") -> str:
        """
        Run DNS diagnostics: resolve a domain, show DNS cache, and
        display configured DNS servers.

        Args:
            domain: Domain to resolve (default: www.google.com).
        """
        result = await run_powershell(
            f"$resolve = Resolve-DnsName '{domain}' -ErrorAction SilentlyContinue | "
            f"Select-Object Name, Type, TTL, IPAddress, NameHost; "
            f"$cache = Get-DnsClientCache -ErrorAction SilentlyContinue | "
            f"Select-Object -First 20 Entry, Name, Type, Data, TimeToLive; "
            f"$servers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.ServerAddresses.Count -gt 0 }} | "
            f"Select-Object InterfaceAlias, AddressFamily, ServerAddresses; "
            f"@{{Resolution=$resolve; Cache=$cache; Servers=$servers}} | "
            f"ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"DNS diagnostics failed: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"DNS Diagnostics (raw):\n{result.stdout}"

        output = f"DNS Diagnostics:\n\n"

        # Resolution
        records = data.get("Resolution", [])
        if not isinstance(records, list):
            records = [records] if records else []
        output += f"Resolution for {domain}:\n"
        for r in records:
            ip = r.get("IPAddress") or r.get("NameHost", "N/A")
            output += f"  {r.get('Type', '?')}: {ip} (TTL: {r.get('TTL', '?')}s)\n"
        output += "\n"

        # DNS servers
        servers = data.get("Servers", [])
        if not isinstance(servers, list):
            servers = [servers] if servers else []
        output += "Configured DNS Servers:\n"
        for s in servers:
            addrs = s.get("ServerAddresses", [])
            if addrs:
                output += f"  {s.get('InterfaceAlias', 'Unknown')}: {', '.join(str(a) for a in addrs)}\n"
        output += "\n"

        # Cache
        cache = data.get("Cache", [])
        if not isinstance(cache, list):
            cache = [cache] if cache else []
        if cache:
            output += f"DNS Cache (recent {len(cache)} entries):\n"
            for c in cache:
                output += f"  {c.get('Name', '?')} -> {c.get('Data', 'N/A')} (TTL: {c.get('TimeToLive', '?')}s)\n"
        return output

    @mcp.tool(name="net_adapter_info", tags={"network"})
    async def adapter_info() -> str:
        """
        Get network adapter details: link speed, status, IP configuration,
        and packet statistics.
        """
        result = await run_powershell(
            "$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
            "Select-Object Name, InterfaceDescription, Status, LinkSpeed, "
            "MacAddress, MediaType; "
            "$ipconfig = Get-NetIPConfiguration | "
            "Select-Object InterfaceAlias, "
            "@{N='IPv4';E={($_.IPv4Address.IPAddress) -join ', '}}, "
            "@{N='Gateway';E={($_.IPv4DefaultGateway.NextHop) -join ', '}}, "
            "@{N='DNS';E={($_.DNSServer.ServerAddresses) -join ', '}}; "
            "$stats = Get-NetAdapterStatistics -ErrorAction SilentlyContinue | "
            "Select-Object Name, ReceivedBytes, SentBytes, "
            "ReceivedUnicastPackets, SentUnicastPackets, "
            "InboundDiscardedPackets, OutboundDiscardedPackets; "
            "@{Adapters=$adapters; IPConfig=$ipconfig; Stats=$stats} | "
            "ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get adapter info: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Adapter Info (raw):\n{result.stdout}"

        output = "Network Adapters:\n\n"

        adapters = data.get("Adapters", [])
        if not isinstance(adapters, list):
            adapters = [adapters] if adapters else []
        ipconfigs = data.get("IPConfig", [])
        if not isinstance(ipconfigs, list):
            ipconfigs = [ipconfigs] if ipconfigs else []
        stats = data.get("Stats", [])
        if not isinstance(stats, list):
            stats = [stats] if stats else []

        # Index IP and stats by interface name
        ip_map = {c.get("InterfaceAlias", ""): c for c in ipconfigs}
        stats_map = {s.get("Name", ""): s for s in stats}

        for a in adapters:
            name = a.get("Name", "Unknown")
            output += f"{name}:\n"
            output += f"  Description: {a.get('InterfaceDescription', 'Unknown')}\n"
            output += f"  Status: {a.get('Status', '?')}\n"
            output += f"  Link Speed: {a.get('LinkSpeed', '?')}\n"
            output += f"  MAC: {a.get('MacAddress', '?')}\n"

            ip = ip_map.get(name, {})
            if ip.get("IPv4"):
                output += f"  IPv4: {ip['IPv4']}\n"
            if ip.get("Gateway"):
                output += f"  Gateway: {ip['Gateway']}\n"
            if ip.get("DNS"):
                output += f"  DNS: {ip['DNS']}\n"

            st = stats_map.get(name, {})
            if st:
                rx = st.get("ReceivedBytes", 0)
                tx = st.get("SentBytes", 0)
                output += f"  Received: {rx / (1024**2):.1f} MB ({st.get('ReceivedUnicastPackets', 0)} packets)\n"
                output += f"  Sent: {tx / (1024**2):.1f} MB ({st.get('SentUnicastPackets', 0)} packets)\n"
                discards = (st.get("InboundDiscardedPackets", 0) or 0) + (st.get("OutboundDiscardedPackets", 0) or 0)
                if discards > 0:
                    output += f"  Discarded Packets: {discards}\n"
            output += "\n"
        return output

    @mcp.tool(name="net_firewall_status", tags={"network"})
    async def firewall_status() -> str:
        """
        Get Windows Firewall profile status (Domain, Private, Public)
        and summary of active rules.
        """
        result = await run_powershell(
            "$profiles = Get-NetFirewallProfile | "
            "Select-Object Name, Enabled, DefaultInboundAction, "
            "DefaultOutboundAction, LogFileName; "
            "$inbound = (Get-NetFirewallRule -Direction Inbound -Enabled True "
            "-ErrorAction SilentlyContinue).Count; "
            "$outbound = (Get-NetFirewallRule -Direction Outbound -Enabled True "
            "-ErrorAction SilentlyContinue).Count; "
            "@{Profiles=$profiles; InboundRules=$inbound; OutboundRules=$outbound} | "
            "ConvertTo-Json -Depth 3"
        )
        if result.return_code != 0:
            return f"Failed to get firewall status: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Firewall Status (raw):\n{result.stdout}"

        output = "Windows Firewall Status:\n\n"

        profiles = data.get("Profiles", [])
        if not isinstance(profiles, list):
            profiles = [profiles] if profiles else []

        for p in profiles:
            enabled = "Enabled" if p.get("Enabled") else "Disabled"
            output += f"{p.get('Name', 'Unknown')} Profile: {enabled}\n"
            output += f"  Default Inbound: {p.get('DefaultInboundAction', '?')}\n"
            output += f"  Default Outbound: {p.get('DefaultOutboundAction', '?')}\n"
            if p.get("LogFileName"):
                output += f"  Log: {p['LogFileName']}\n"
            output += "\n"

        output += f"Active Inbound Rules: {data.get('InboundRules', '?')}\n"
        output += f"Active Outbound Rules: {data.get('OutboundRules', '?')}\n"
        return output

    @mcp.tool(name="net_active_connections", tags={"network"})
    async def active_connections(state: str = "Established") -> str:
        """
        List active TCP connections with owning process names.

        Args:
            state: Filter by connection state — Established, Listen, TimeWait,
                   CloseWait, or All (default: Established).
        """
        state_filter = ""
        if state.lower() != "all":
            state_filter = f" -State {state}"

        result = await run_powershell(
            f"Get-NetTCPConnection{state_filter} -ErrorAction SilentlyContinue | "
            f"Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, "
            f"State, OwningProcess, "
            f"@{{N='ProcessName';E={{(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}}} | "
            f"ConvertTo-Json"
        )
        if result.return_code != 0:
            return f"Failed to get connections: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Connections (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        output = f"Active TCP Connections (state: {state}):\n\n"
        output += f"{'Local':<25} {'Remote':<25} {'State':<15} {'Process':<20}\n"
        output += "-" * 85 + "\n"

        for c in data:
            local = f"{c.get('LocalAddress', '?')}:{c.get('LocalPort', '?')}"
            remote = f"{c.get('RemoteAddress', '?')}:{c.get('RemotePort', '?')}"
            pname = c.get("ProcessName", "?") or f"PID:{c.get('OwningProcess', '?')}"
            output += f"{local:<25} {remote:<25} {c.get('State', '?'):<15} {pname:<20}\n"

        output += f"\nTotal: {len(data)} connections\n"
        return output

    @mcp.tool(name="net_speed_test", tags={"network"})
    async def speed_test() -> str:
        """
        Run a network speed test measuring download/upload speed and latency.
        Uses Speedtest CLI if installed, otherwise falls back to basic latency test.
        """
        if AVAILABLE_TOOLS["speedtest"]:
            result = await run_command(
                "speedtest", ["--format=json", "--accept-license"],
                timeout=120,
            )
            if result.return_code == 0:
                try:
                    data = json.loads(result.stdout)
                    output = "Network Speed Test — via Speedtest CLI:\n\n"
                    output += f"Server: {data.get('server', {}).get('name', '?')} ({data.get('server', {}).get('location', '?')})\n"
                    output += f"ISP: {data.get('isp', '?')}\n"

                    dl = data.get("download", {})
                    ul = data.get("upload", {})
                    ping = data.get("ping", {})

                    if dl.get("bandwidth"):
                        output += f"Download: {dl['bandwidth'] * 8 / 1_000_000:.1f} Mbps\n"
                    if ul.get("bandwidth"):
                        output += f"Upload: {ul['bandwidth'] * 8 / 1_000_000:.1f} Mbps\n"
                    if ping.get("latency"):
                        output += f"Latency: {ping['latency']:.1f} ms\n"
                    if ping.get("jitter"):
                        output += f"Jitter: {ping['jitter']:.1f} ms\n"

                    result_url = data.get("result", {}).get("url")
                    if result_url:
                        output += f"\nResult URL: {result_url}\n"
                    return output
                except json.JSONDecodeError:
                    return f"Speed Test (raw):\n{result.stdout}"

        # Fallback: basic latency test
        result = await run_powershell(
            "$targets = @('8.8.8.8', '1.1.1.1', 'www.google.com'); "
            "$results = foreach ($t in $targets) { "
            "  $ping = Test-Connection -ComputerName $t -Count 5 "
            "    -ErrorAction SilentlyContinue; "
            "  if ($ping) { "
            "    @{Target=$t; "
            "      AvgLatency=($ping | Measure-Object -Property Latency -Average).Average; "
            "      MinLatency=($ping | Measure-Object -Property Latency -Minimum).Minimum; "
            "      MaxLatency=($ping | Measure-Object -Property Latency -Maximum).Maximum; "
            "      PacketLoss=((5 - $ping.Count) / 5 * 100)} "
            "  } "
            "}; "
            "$results | ConvertTo-Json"
        )
        if result.return_code != 0:
            return f"Speed test failed: {result.stderr}"

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return f"Speed Test (raw):\n{result.stdout}"

        if not isinstance(data, list):
            data = [data]

        output = "Network Latency Test (install Speedtest CLI for full speed test):\n\n"
        for t in data:
            output += f"{t.get('Target', '?')}:\n"
            output += f"  Avg Latency: {t.get('AvgLatency', 0):.1f} ms\n"
            output += f"  Min: {t.get('MinLatency', 0):.1f} ms / Max: {t.get('MaxLatency', 0):.1f} ms\n"
            output += f"  Packet Loss: {t.get('PacketLoss', 0):.0f}%\n\n"
        return output

    @mcp.tool(name="net_wifi_diagnostics", tags={"network"})
    async def wifi_diagnostics() -> str:
        """
        Get WiFi diagnostics: current connection info (signal strength,
        channel, speed) and available networks.
        """
        # Current WiFi interface info
        iface_result = await run_command("netsh", ["wlan", "show", "interfaces"])
        # Available networks
        networks_result = await run_command("netsh", ["wlan", "show", "networks", "mode=bssid"])

        output = "WiFi Diagnostics:\n\n"

        if iface_result.return_code == 0 and iface_result.stdout:
            output += "Current Connection:\n"
            for line in iface_result.stdout.split("\n"):
                line = line.strip()
                if any(k in line.lower() for k in [
                    "ssid", "signal", "channel", "radio", "receive rate",
                    "transmit rate", "state", "authentication", "band",
                ]):
                    output += f"  {line}\n"
            output += "\n"
        else:
            output += "No WiFi interface detected or WiFi is disabled.\n\n"

        if networks_result.return_code == 0 and networks_result.stdout:
            output += "Available Networks:\n"
            current_network = ""
            for line in networks_result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    current_network = line
                    output += f"\n  {line}\n"
                elif any(k in line.lower() for k in [
                    "signal", "channel", "radio", "authentication", "encryption",
                ]):
                    output += f"    {line}\n"

        return output
