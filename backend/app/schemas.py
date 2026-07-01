from typing import Literal

from pydantic import BaseModel


class ClientCreate(BaseModel):
    display_name: str
    country_code: str


class RoleGrant(BaseModel):
    role: Literal["owner_admin", "bookkeeper", "read_only_auditor"]
