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

    # API runtime settings
    api_v1_prefix: str = "/api/v1"
    host: str = "0.0.0.0"
    port: int = 8000

    database_url: str

    # Load values from the local .env file when present
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


# Single settings instance shared across the application
settings = Settings()
