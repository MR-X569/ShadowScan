"""Application configuration for the FastAPI backend.

This module centralizes environment-based settings without introducing
any database or authentication logic.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


# General application settings
class Settings(BaseSettings):
    """Load configuration values from environment variables and .env files."""

    # Application identity
    app_name: str = "ShadowScan"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False

    # Security settings
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int

    # Google OAuth settings. They remain optional so email/password
    # authentication can run when Google OAuth has not been configured.
    google_client_id: str | None = None
    google_client_secret: str | None = None
    google_redirect_uri: str | None = None

    # Frontend URL — used to redirect browser after Google OAuth callback.
    # Override with FRONTEND_URL env var in production.
    frontend_url: str = "http://localhost:3000"

    # API runtime settings
    api_v1_prefix: str = "/api/v1"
    host: str = "0.0.0.0"
    port: int = 8000

    database_url: str

    # SMTP settings for email delivery
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_email: str = ""
    smtp_password: str = ""
    smtp_from: str = "ShadowScan"

    # AI Security Analyst (Ollama) settings
    ai_enabled: bool = True
    ai_provider: str = "ollama"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:0.5b"
    ollama_timeout: float = 60.0


    # Load values from the local .env file when present
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


# Single settings instance shared across the application
settings = Settings()

