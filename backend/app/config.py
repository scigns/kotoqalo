from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_database_url: str
    # Left blank until the Auth0 tenant is provisioned; real requests will
    # fail meaningfully (not silently) against an empty domain/audience.
    auth0_domain: str = ""
    auth0_audience: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
