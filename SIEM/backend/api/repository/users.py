from datetime import datetime, timezone
from sqlalchemy.orm import Session
from api.models.users import users, refresh_tokens


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_email(self, email: str) -> users | None:
        return self.db.query(users).filter(users.email == email).first()

    def get_by_id(self, users_id: int) -> users | None:
        return self.db.query(users).filter(users.users_id == users_id).first()

    def create(self, username: str, email: str, hashed_password: str, role_id: int) -> users:
        user = users(username=username, email=email, password=hashed_password, role_id=role_id)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def save(self, user: users) -> users:
        self.db.commit()
        self.db.refresh(user)
        return user


class RefreshTokenRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, jti: str, users_id: int, expires_at: datetime) -> refresh_tokens:
        token = refresh_tokens(jti=jti, users_id=users_id, expires_at=expires_at)
        self.db.add(token)
        self.db.commit()
        return token

    def get_by_jti(self, jti: str) -> refresh_tokens | None:
        return self.db.query(refresh_tokens).filter(refresh_tokens.jti == jti).first()

    def revoke(self, token: refresh_tokens) -> None:
        token.revoked = True
        self.db.commit()

    def revoke_all_for_user(self, users_id: int) -> None:
        self.db.query(refresh_tokens).filter(
            refresh_tokens.users_id == users_id,
            refresh_tokens.revoked == False,
        ).update({"revoked": True})
        self.db.commit()