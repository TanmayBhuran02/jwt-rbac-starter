"""Authentication-related Pydantic schemas."""

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Credentials for user login."""

    email: str = Field(
        ..., description="User email address", json_schema_extra={"examples": ["user@example.com"]}
    )
    password: str = Field(
        ..., description="User password", json_schema_extra={"examples": ["secretpassword"]}
    )


class TokenResponse(BaseModel):
    """JWT token pair returned on login or refresh."""

    access_token: str = Field(..., description="Short-lived access token")
    refresh_token: str = Field(..., description="Long-lived refresh token")
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """Request body for token refresh."""

    refresh_token: str = Field(..., description="The refresh token to exchange")


class PasswordChangeRequest(BaseModel):
    """Request body for changing the current user's password."""

    current_password: str = Field(..., description="Current password for verification")
    new_password: str = Field(..., min_length=8, description="New password (minimum 8 characters)")


class TokenInfo(BaseModel):
    """Decoded JWT payload returned by the introspection endpoint."""

    sub: str = Field(..., description="User ID")
    roles: list[str] = Field(default_factory=list, description="Assigned roles")
    permissions: list[str] = Field(default_factory=list, description="Granted permissions")
    exp: int = Field(..., description="Expiry timestamp (epoch)")
    jti: str = Field(..., description="Unique token ID")
    token_type: str = Field(..., alias="type", description="Token type (access/refresh)")
    iss: str | None = Field(None, description="Issuer (if configured)")
