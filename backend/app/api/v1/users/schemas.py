from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, EmailStr, Field

DBRole = Literal["reader", "analyst", "rssi", "auditor", "admin"]


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: DBRole = "analyst"
    mfa_enabled: bool = False
    org_scope: Optional[str] = Field(default=None, max_length=64)


class UserRoleUpdate(BaseModel):
    role: DBRole


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[DBRole] = None
    org_scope: Optional[str] = Field(default=None, max_length=64)
    is_active: Optional[bool] = None


class SetActiveRequest(BaseModel):
    is_active: bool


class UserOut(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    role: str
    org_scope: Optional[str] = None
    is_active: bool
    mfa_enabled: bool = False
    failed_login_count: int = 0
    locked_until: Optional[str] = None
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None


class UserListResponse(BaseModel):
    total: int
    page: int
    size: int
    results: List[UserOut]


class DeleteUserResponse(BaseModel):
    id: str
    deleted: bool
