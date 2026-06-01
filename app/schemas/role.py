"""Role and permission Pydantic schemas."""

from pydantic import BaseModel, Field


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


class PermissionAssignment(BaseModel):
    """Request body for assigning permissions to a role."""

    permissions: list[str] = Field(
        ...,
        min_length=1,
        description="List of permission names to assign to the role",
        json_schema_extra={"examples": [["users:read", "users:write"]]},
    )
