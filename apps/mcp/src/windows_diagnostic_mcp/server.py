import ctypes
import sys
import os
import logging
import argparse
from fastmcp import FastMCP

from .config import settings
from .tools.hardware_tools import register_hardware_tools
from .tools.os_tools import register_os_tools
from .tools.performance_tools import register_performance_tools
from .tools.network_tools import register_network_tools
from .tools.security_tools import register_security_tools

logger = logging.getLogger(settings.MCP_NAME)

mcp = FastMCP(settings.MCP_NAME)


def parse_arguments():
    """Parse command line arguments for server configuration."""
    parser = argparse.ArgumentParser(description='Windows Diagnostic MCP Server')

    parser.add_argument('--mode',
                       choices=['http', 'sse', 'stdio'],
                       default='http',
                       help='Server mode: http (streamable), sse (server-sent events), or stdio')

    parser.add_argument('--host',
                       default=settings.HOST,
                       help=f'Host to bind the server to (default: {settings.HOST})')

    parser.add_argument('--port',
                       type=int,
                       default=settings.HTTP_PORT,
                       help=f'Port to bind the server to (default: {settings.HTTP_PORT})')

    return parser.parse_args()


def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False


def relaunch_as_admin() -> None:
    """Re-launch the current script with elevated (admin) privileges via UAC."""
    script = os.path.abspath(sys.argv[0])
    params = " ".join(sys.argv[1:])
    cwd = os.getcwd()
    # When launched via an installed entry point (e.g. uv run), sys.argv[0]
    # is an .exe wrapper.  Elevate the wrapper directly so it can locate its
    # own Python interpreter.  For plain .py scripts, elevate via python.exe.
    if script.lower().endswith((".exe", ".cmd", ".bat")):
        exe = script
        args = params
    else:
        exe = sys.executable
        args = f'"{script}" {params}'
    # ShellExecuteW returns an HINSTANCE > 32 on success.
    # Pass cwd so the elevated process doesn't start in System32.
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe, args, cwd, 1
    )
    if ret <= 32:
        print("Failed to elevate privileges (UAC cancelled or error).")
        sys.exit(1)
    # The elevated process is now running separately; exit this one.
    sys.exit(0)


def main():
    """Main function with argument parsing."""
    args = parse_arguments()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

    # Admin privilege handling depends on transport mode.
    # stdio: Claude Code owns the process stdin/stdout — UAC relaunch would break
    #        the pipe, so we only log a warning and let tools degrade gracefully.
    # http/sse: standalone process, safe to relaunch elevated via UAC.
    if not is_admin():
        if args.mode == "stdio":
            logger.warning(
                "Running WITHOUT administrator privileges. "
                "Some diagnostic tools will return limited data. "
                "To get full results, launch Claude Code from an elevated terminal."
            )
        else:
            print("Administrator privileges required. Requesting elevation...")
            relaunch_as_admin()

    logger.info("Starting %s in %s mode on %s:%s", settings.MCP_NAME, args.mode, args.host, args.port)

    # Register diagnostic tool categories
    register_hardware_tools(mcp)
    register_os_tools(mcp)
    register_performance_tools(mcp)
    register_network_tools(mcp)
    register_security_tools(mcp)

    logger.info("All diagnostic tools registered")

    run_kwargs = {"transport": args.mode}
    if args.mode != "stdio":
        run_kwargs["host"] = args.host
        run_kwargs["port"] = args.port
    mcp.run(**run_kwargs)


if __name__ == "__main__":
    main()
