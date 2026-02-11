# windows-diagnostic-mcp

Diagnostic MCP tooling for Claude Code or any LLM. Uses [FastMCP](https://github.com/jlowin/fastmcp) and is deployable in multiple transport modes (STDIO, SSE, Streamable HTTP).

## Requirements

- **Python** >= 3.11
- **UV** (fast Python package manager)

### Installing UV

**Linux / macOS:**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## Getting Started

Clone the repository and install dependencies:

```bash
git clone https://github.com/ZynBee/windows-diagnostic-mcp.git
cd windows-diagnostic-mcp/apps/mcp
uv sync
```

## Usage

The server supports three transport modes: **stdio**, **sse**, and **http** (streamable).

### STDIO Mode (Claude Code / Claude Desktop)

```bash
cd apps/mcp
uv run windows-diagnostic-mcp --mode stdio
```

### HTTP Mode (default)

```bash
cd apps/mcp
uv run windows-diagnostic-mcp --mode http --host 0.0.0.0 --port 8000
```

### SSE Mode

```bash
cd apps/mcp
uv run windows-diagnostic-mcp --mode sse --host 0.0.0.0 --port 8001
```

## Claude Code Integration

The server launches in **stdio** mode for Claude Code. The configuration is defined in [apps/mcp/manifest.json](apps/mcp/manifest.json).

To use this MCP with Claude Code you need to update the `--directory` path in `manifest.json` to point to the location where the Claude extension expects to find it. By default, Claude Desktop unpacks extensions to:

```
%APPDATA%\Claude\Claude Extensions\<extension-id>
```

Open [apps/mcp/manifest.json](apps/mcp/manifest.json) and update the `--directory` argument to match your install location:

```json
{
    "server": {
        "mcp_config": {
            "command": "uv",
            "args": [
                "--directory",
                "C:\\Users\\<YOUR_USERNAME>\\AppData\\Roaming\\Claude\\Claude Extensions\\local.unpacked.zynbee.windows-diagnostic-mcp",
                "run",
                "windows-diagnostic-mcp",
                "--mode",
                "stdio"
            ]
        }
    }
}
```

Replace `<YOUR_USERNAME>` with your Windows username (or adjust the full path if you installed the extension elsewhere).

> **Note:** Some diagnostic tools require administrator privileges. When running in stdio mode, the server cannot elevate via UAC (it would break the pipe). For full results, launch Claude Code from an elevated (Administrator) terminal.

## Tool Categories

| Category | Description |
|---|---|
| **Hardware** | Disk health (S.M.A.R.T.), disk benchmarks, memory diagnostics |
| **OS** | System information, event logs, installed software, Windows Update status |
| **Performance** | CPU/memory/disk usage, process listing, resource monitoring |
| **Network** | Adapter info, connectivity tests, DNS diagnostics, routing |
| **Security** | Firewall status, antivirus state, Windows Defender scans |

## Configuration

The server is configured via launch command and will fallback to environment variables or a `.env` file if not provided. Key settings:

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address for HTTP/SSE modes |
| `HTTP_PORT` | `8000` | Port for HTTP mode |
| `SSE_PORT` | `8001` | Port for SSE mode |
| `COMMAND_TIMEOUT` | `120` | Timeout (seconds) for diagnostic commands |
| `BENCHMARK_TIMEOUT` | `300` | Timeout (seconds) for benchmark operations |

## License

See [LICENSE](LICENSE) for details.
