"""Role and permission Pydantic schemas."""

from pydantic import BaseModel


class PermissionOut(BaseModel):
    """Public permission representation."""

    id: int
    name: str

    model_config = {"from_attributes": True}


class RoleOut(BaseModel):
    """Public role representation with nested permissions."""

    id: int
    name: str
    permissions: list[PermissionOut] = []

    model_config = {"from_attributes": True}
