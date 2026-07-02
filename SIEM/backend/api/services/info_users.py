from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import UploadFile

from api.repository.info_users import InfoUserRepository
from api.schemas.info_users import InfoUserCreate, InfoUserUpdate
from api.services.info_users import save_profile_picture, delete_old_picture
from api.models.users import info_users
from api.middlewares.exception import InfoUserAlreadyExistsError, InfoUserNotFoundError


class InfoUserService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = InfoUserRepository(db)

    async def create_profile(self, users_id: int, data: InfoUserCreate, picture: UploadFile | None) -> info_users:
        if self.repo.get_by_user_id(users_id):
            raise InfoUserAlreadyExistsError()

        picture_path = None
        if picture is not None:
            picture_path = await save_profile_picture(picture)

        payload = data.model_dump()
        payload["picture"] = picture_path
        return self.repo.create(users_id=users_id, data=payload)

    def get_profile(self, users_id: int) -> info_users:
        info_user = self.repo.get_by_user_id(users_id)
        if not info_user:
            raise InfoUserNotFoundError()
        return info_user

    async def update_profile(self, users_id: int, data: InfoUserUpdate, picture: UploadFile | None) -> info_users:
        info_user = self.repo.get_by_user_id(users_id)
        if not info_user:
            raise InfoUserNotFoundError()

        update_data = data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(info_user, field, value)

        if picture is not None:
            delete_old_picture(info_user.picture)  # supprime l'ancienne image du disque
            info_user.picture = await save_profile_picture(picture)

        info_user.updated_at = datetime.now(timezone.utc)
        return self.repo.save(info_user)

    def delete_profile(self, users_id: int) -> None:
        info_user = self.repo.get_by_user_id(users_id)
        if not info_user:
            raise InfoUserNotFoundError()
        delete_old_picture(info_user.picture)
        self.repo.delete(info_user)