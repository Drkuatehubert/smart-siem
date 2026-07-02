from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address

from api.schemas.users import (
    UserRegister, UserLogin, UserProfile, Token,
    RefreshRequest, LogoutRequest, ChangePassword,
)
from api.services.users import AuthService
from api.middlewares.auth import get_auth_service, get_current_user
from api.middlewares.exception import (
    UserAlreadyExistsError, InvalidCredentialsError, AccountInactiveError,
    InvalidTokenError, UserNotFoundError, SamePasswordError,
)
from api.models.users import users

router = APIRouter(prefix="/siem/api", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)

# -- CONFIGURATION DES API DE GESTION DES UTILISATUER --
# Route d'inscription d'un nouvel utilisateur : http://127.0.0.1:8000/siem/api/register/
@router.post("/register/", response_model=UserProfile, status_code=status.HTTP_201_CREATED)
def register(data: UserRegister, service: AuthService = Depends(get_auth_service)):
    try:
        return service.register(data)
    except UserAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Impossible de créer le compte avec ces informations",
        )

# Route de connexion d'un utilisateur : http://127.0.0.1:8000/siem/api/login/
@router.post("/login/", response_model=Token)
@limiter.limit("5/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthService = Depends(get_auth_service),
):
    try:
        return service.login(form_data.username, form_data.password)
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
        )
    except AccountInactiveError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Compte désactivé")


# Route de déconnexion d'un nouvelle utilisateur : http://127.0.0.1:8000/siem/api/logout/
@router.post("/logout/", status_code=status.HTTP_204_NO_CONTENT)
def logout(data: LogoutRequest, service: AuthService = Depends(get_auth_service)):
    try:
        service.logout(data.refresh_token)
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide ou déjà révoqué")


# Route de rafraîchissement d'un token : http://127.0.0.1:8000/siem/api/refresh/
@router.post("/refresh/", response_model=Token)
def refresh(data: RefreshRequest, service: AuthService = Depends(get_auth_service)):
    try:
        return service.refresh_tokens(data.refresh_token)
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Refresh token invalide ou expiré")


# Route de mise à jour du mot de passe d'un utilisateur : http://127.0.0.1:8000/siem/api/change-password/
@router.put("/change-password/", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    data: ChangePassword,
    current_user: users = Depends(get_current_user),
    service: AuthService = Depends(get_auth_service),
):
    try:
        service.change_password(current_user, data.old_password, data.new_password)
    except InvalidCredentialsError:
        raise HTTPException(status_code=400, detail="Ancien mot de passe incorrect")
    except SamePasswordError:
        raise HTTPException(status_code=400, detail="Le nouveau mot de passe doit être différent de l'ancien")

# Route permettant de récupérer les informations de l'utilisateur connecté : http://127.0.0.1:8000/siem/api/me/
@router.get("/me/", response_model=UserProfile)
def get_my_profile(current_user: users = Depends(get_current_user)):
    return current_user


# Route de récupération des informations d'un utilisateur spécifique : http://127.0.0.1:8000/siem/api/users/{users_id}/
@router.get("/users/{users_id}/", response_model=UserProfile)
def get_user_by_id(
    users_id: int,
    current_user: users = Depends(get_current_user),  # protège la route
    service: AuthService = Depends(get_auth_service),
):
    try:
        return service.get_profile(users_id)
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    
# Route permettant de récupérer tous les utilisateurs : http://127.0.0.1:8000/siem/api/users/all/


# Route permettant de supprimer un utilisateur : 
