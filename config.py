from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
  # 1. Define fields with intelligent default fallbacks
  DATABASE_URL: str = "sqlite:///./app.db"
  ENVIRONMENT: str = "development"
  DEBUG: bool = True

  # 2. Configure Pydantic to read from system env vars first,
  # falling back to an optional .env file if it exists.
  model_config = SettingsConfigDict(
      env_file=".env",
      env_file_encoding="utf-8",
      extra="ignore",  # Ignores extraneous env variables safely
  )


@lru_cache
def get_settings() -> Settings:
  """Cached settings instance to prevent redundant file parsing."""
  return Settings()


# Expose a global settings object for your application
settings = get_settings()