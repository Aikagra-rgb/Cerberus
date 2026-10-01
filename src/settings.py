"""
Application settings configuration for Cerberus.
Validated via Pydantic BaseSettings from environment variables and .env file.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core Security Credentials
    ADMIN_USERNAME: str = Field(default="", description="Administrator username")
    ADMIN_PASSWORD: str = Field(default="", description="Administrator password")

    # Logging & Observability
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_JSON: bool = Field(default=False, description="Enable JSON structured logging")
    LOG_FILE: str | None = Field(default=None, description="Optional path for rotating log file")

    # CORS & Domains
    ALLOWED_ORIGINS: str = Field(default="", description="Comma-separated allowed CORS origins")
    VERCEL_DOMAINS: str = Field(
        default="", description="Comma-separated allowed Vercel frontend domains"
    )

    # LLM & Multi-Agent Pipeline
    NVIDIA_BASE_URL: str = Field(
        default="https://integrate.api.nvidia.com/v1",
        description="NVIDIA NIM base URL",
    )
    NEMOTRON_API_KEY: str = Field(default="", description="NVIDIA Nemotron API Key")
    DEEPSEEK_API_KEY: str = Field(default="", description="DeepSeek API Key")
    NEMOTRON_MODEL: str = Field(
        default="nvidia/llama-3.1-nemotron-70b-instruct",
        description="Model name for Nemotron triage",
    )
    DEEPSEEK_MODEL: str = Field(
        default="deepseek-ai/deepseek-v4-0324",
        description="Model name for DeepSeek remediation",
    )
    AGENT_TIMEOUT_SECONDS: int = Field(
        default=30, ge=1, le=180, description="Timeout for agent execution in seconds"
    )

    # RAG Settings
    MITRE_DATA_PATH: str | None = Field(
        default=None, description="Path to MITRE ATT&CK JSON dataset"
    )
    RAG_TOP_K: int = Field(default=3, ge=1, le=20, description="Top K documents for RAG retrieval")

    def get_allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    def get_vercel_domains_list(self) -> list[str]:
        return [o.strip() for o in self.VERCEL_DOMAINS.split(",") if o.strip()]


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
