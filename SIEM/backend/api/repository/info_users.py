from sqlalchemy.orm import Session
from api.models.users import info_users


class InfoUserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_user_id(self, users_id: int) -> info_users | None:
        return self.db.query(info_users).filter(info_users.users_id == users_id).first()

    def create(self, users_id: int, data: dict) -> info_users:
        info_users = info_users(users_id=users_id, **data)
        self.db.add(info_users)
        self.db.commit()
        self.db.refresh(info_users)
        return info_users

    def save(self, info_user: info_users) -> info_users:
        self.db.commit()
        self.db.refresh(info_user)
        return info_user

    def delete(self, info_user: info_users) -> None:
        self.db.delete(info_user)
        self.db.commit()