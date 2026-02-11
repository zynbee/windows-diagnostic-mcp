"""Application configuration settings"""

from pydantic_settings import BaseSettings
from pydantic import ConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    model_config = ConfigDict(env_file=".env", case_sensitive=True)

    # Server Configuration
    HOST: str = "0.0.0.0"
    HTTP_PORT: int = 8000
    SSE_PORT: int = 8001
    RELOAD: bool = False

    # Environment
    ENVIRONMENT: str = "dev"

    # MCP Configuration
    MCP_NAME: str = "windows_diagnostic_mcp"
    MCP_DESCRIPTION: str = "Windows system diagnostics MCP server"

    # Diagnostic command timeouts (seconds)
    COMMAND_TIMEOUT: int = 120
    BENCHMARK_TIMEOUT: int = 300

    # External tool paths (auto-detected on PATH if left as default)
    SMARTCTL_PATH: str = "smartctl"
    DISKSPD_PATH: str = "diskspd"
    NVIDIA_SMI_PATH: str = "nvidia-smi"
    SPEEDTEST_PATH: str = "speedtest"


# Global settings instance
settings = Settings()
