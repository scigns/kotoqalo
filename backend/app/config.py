from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_database_url: str
    # Left blank until the Auth0 tenant is provisioned; real requests will
    # fail meaningfully (not silently) against an empty domain/audience.
    auth0_domain: str = ""
    auth0_audience: str = ""

    # Selects which KeyProvider backs field-level encryption (see
    # app/crypto.py). "ephemeral" (dev/test only -- a random key held in
    # memory for the process lifetime, never persisted) is the only
    # implemented option today; "infisical" is the intended production
    # backend, stubbed until a real Infisical project/machine identity
    # exists.
    key_provider: Literal["ephemeral", "infisical"] = "ephemeral"
    infisical_host: str = ""
    infisical_project_id: str = ""
    infisical_environment: str = ""
    infisical_secret_path: str = "/"
    infisical_secret_name: str = ""
    infisical_client_id: str = ""
    infisical_client_secret: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
