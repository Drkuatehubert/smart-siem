from typing import Optional, List
from pydantic import BaseModel
class UserCreate(BaseModel):
    username: str; email: Optional[str] = None; password: str; role_id: str; org_scope: Optional[str] = None
class UserOut(BaseModel):
    id: str; username: str; email: Optional[str]=None; role_id: str; org_scope: Optional[str]=None; is_active: bool
class UserListResponse(BaseModel):
    total: int; page: int; size: int; results: List[UserOut]
