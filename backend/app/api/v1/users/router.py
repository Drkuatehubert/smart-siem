from fastapi import APIRouter, Depends
from app.api.v1.users.schemas import UserCreate, UserListResponse
from app.api.v1.users.service import list_users, create_user
from app.core.rbac import require_admin
from app.api.v1.auth.service import write_audit_log
router = APIRouter(prefix="/users", tags=["Utilisateurs"])
@router.get("", response_model=UserListResponse)
async def get_users(page:int=1,size:int=50,_=Depends(require_admin)):
    return await list_users(page,size)
@router.post("",status_code=201)
async def create(body:UserCreate,current_user=Depends(require_admin)):
    result=await create_user(body.model_dump())
    await write_audit_log(current_user["sub"],"creation_utilisateur",target_entity="utilisateur",target_id=result["id"])
    return result
