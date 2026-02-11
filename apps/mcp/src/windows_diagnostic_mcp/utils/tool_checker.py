"""Detect which optional external CLI tools are installed."""

import shutil
import logging

logger = logging.getLogger(__name__)

# External tools and their executable names
_TOOL_EXECUTABLES = {
    "smartctl": "smartctl",
    "diskspd": "diskspd",
    "nvidia_smi": "nvidia-smi",
    "speedtest": "speedtest",
}


def _check_tools() -> dict[str, bool]:
    """Check which external tools are available on PATH."""
    available = {}
    for tool_key, exe_name in _TOOL_EXECUTABLES.items():
        path = shutil.which(exe_name)
        available[tool_key] = path is not None
        if path:
            logger.info("External tool found: %s -> %s", exe_name, path)
        else:
            logger.info("External tool not found: %s (fallback will be used)", exe_name)
    return available


AVAILABLE_TOOLS: dict[str, bool] = _check_tools()
