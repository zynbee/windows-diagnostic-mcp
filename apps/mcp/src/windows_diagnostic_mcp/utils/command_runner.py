"""Async subprocess runner for PowerShell and CLI commands."""

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result from a subprocess execution."""
    stdout: str
    stderr: str
    return_code: int
    timed_out: bool


async def run_powershell(
    script: str,
    timeout: int = 60,
) -> CommandResult:
    """
    Run a PowerShell script and return the result.

    Args:
        script: PowerShell script/command to execute.
        timeout: Maximum execution time in seconds.

    Returns:
        CommandResult with stdout, stderr, return_code, and timed_out flag.
    """
    args = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        script,
    ]
    return await _run_subprocess(args, timeout)


async def run_command(
    exe: str,
    args: Optional[list[str]] = None,
    timeout: int = 60,
) -> CommandResult:
    """
    Run an arbitrary CLI command and return the result.

    Args:
        exe: Executable name or path.
        args: List of command-line arguments.
        timeout: Maximum execution time in seconds.

    Returns:
        CommandResult with stdout, stderr, return_code, and timed_out flag.
    """
    cmd = [exe] + (args or [])
    return await _run_subprocess(cmd, timeout)


async def _run_subprocess(cmd: list[str], timeout: int) -> CommandResult:
    """Internal helper to run a subprocess with timeout handling."""
    logger.debug("Running command: %s (timeout=%ds)", cmd[0], timeout)
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            logger.warning("Command timed out after %ds: %s", timeout, cmd[0])
            return CommandResult(
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                return_code=-1,
                timed_out=True,
            )

        stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

        if process.returncode != 0:
            logger.debug(
                "Command exited with code %d: %s\nstderr: %s",
                process.returncode, cmd[0], stderr[:200],
            )

        return CommandResult(
            stdout=stdout,
            stderr=stderr,
            return_code=process.returncode,
            timed_out=False,
        )

    except FileNotFoundError:
        logger.error("Command not found: %s", cmd[0])
        return CommandResult(
            stdout="",
            stderr=f"Command not found: {cmd[0]}",
            return_code=-1,
            timed_out=False,
        )
    except Exception as e:
        logger.error("Failed to run command %s: %s", cmd[0], e)
        return CommandResult(
            stdout="",
            stderr=str(e),
            return_code=-1,
            timed_out=False,
        )
