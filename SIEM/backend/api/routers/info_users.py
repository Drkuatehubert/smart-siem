# -- CONFIGURATION DES INFORMATIONS SUPPLEMENTAIRE DES UTILISATEURS --
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session

from api.schemas.info_users import InfoUserCreate, InfoUserUpdate, InfoUserOut
from api.services.info_users import InfoUserService
from api.middlewares.auth import get_current_user
from api.config.database import get_db
from api.middlewares.exception import InfoUserAlreadyExistsError, InfoUserNotFoundError, InvalidFileError
from api.models.users import users

router = APIRouter(prefix="/siem/api/profile", tags=["info_users"])

def get_info_user_service(db: Session = Depends(get_db)) -> InfoUserService:
    return InfoUserService(db)

# Route permettant de renseigner les informations supplémentaire d'un utilisateur : http://127.0.0.1:8000/siem/api/profile/created/
@router.post("/created/", response_model=InfoUserOut, status_code=status.HTTP_201_CREATED)
async def create_my_profile(
    data: InfoUserCreate = Depends(InfoUserCreate.as_form),
    picture: UploadFile | None = File(None),
    current_user: users = Depends(get_current_user),
    service: InfoUserService = Depends(get_info_user_service),
):
    try:
        return await service.create_profile(current_user.users_id, data, picture)
    except InfoUserAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Un profil existe déjà pour cet utilisateur, utilisez PATCH pour le modifier",
        )
    except InvalidFileError as e:
        raise HTTPException(status_code=400, detail=str(e))

# Route permettant de mettre à jour les informations supplémentaire d'un utilisateur X : http://127.0.0.1:8000/siem/api/profile/updated/
@router.patch("/updated/", response_model=InfoUserOut)
async def update_my_profile(
    data: InfoUserUpdate = Depends(InfoUserUpdate.as_form),
    picture: UploadFile | None = File(None),
    current_user: users = Depends(get_current_user),
    service: InfoUserService = Depends(get_info_user_service),
):
    try:
        return await service.update_profile(current_user.users_id, data, picture)
    except InfoUserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Aucun profil à mettre à jour, créez-le d'abord avec POST",
        )
    except InvalidFileError as e:
        raise HTTPException(status_code=400, detail=str(e))

# Route permettant de récupérer les informations supplémentaires d'un utilisateur connecté : http://127.0.0.1:8000/siem/api/profile/me/
@router.get("/me/", response_model=InfoUserOut)
def get_my_profile(
    current_user: users = Depends(get_current_user),
    service: InfoUserService = Depends(get_info_user_service),
):
    try:
        return service.get_profile(current_user.users_id)
    except InfoUserNotFoundError:
        raise HTTPException(status_code=404, detail="Profil non renseigné")

# Route permettant de récupérer les informations supplémentaire d'un utilisateur spécifique : http://127.0.0.1:8000/siem/api/profile/users/{users_id}/
@router.get("/users/{users_id}", response_model=InfoUserOut)
def get_profile_by_user_id(
    users_id: int,
    current_user: users = Depends(get_current_user),
    service: InfoUserService = Depends(get_info_user_service),
):
    try:
        return service.get_profile(users_id)
    except InfoUserNotFoundError:
        raise HTTPException(status_code=404, detail="Profil introuvable")