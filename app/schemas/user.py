"""User-related Pydantic schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from app.schemas.role import RoleOut


class UserCreate(BaseModel):
    """Schema for creating a new user account."""

    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, description="Password (minimum 8 characters)")
    role_name: str | None = Field(None, description="Optional role to assign during registration (defaults to 'USER')")


class UserOut(BaseModel):
    """Public user representation returned by API endpoints."""

    id: UUID
    email: EmailStr
    is_active: bool
    created_at: datetime
    roles: list[RoleOut] = []

    model_config = {"from_attributes": True}


class UserInDB(UserOut):
    """Internal user representation including the hashed password."""

    hashed_password: str


class RoleAssignment(BaseModel):
    """Request body for assigning or revoking a role from a user."""

    role_name: str = Field(
        ...,
        description="Name of the role to assign/revoke",
        json_schema_extra={"examples": ["ADMIN"]},
    )
    action: str = Field("assign", description="'assign' or 'revoke'", pattern="^(assign|revoke)$")
