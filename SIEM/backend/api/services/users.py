from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from api.repository.users import UserRepository
from api.schemas.users import UserRegister, Token
from api.models.users import users
from api.middlewares.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token,
)
from api.middlewares.exception import (
    UserAlreadyExistsError, InvalidCredentialsError,
    AccountLockedError, AccountInactiveError, InvalidTokenError,
)

MAX_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=15)


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = UserRepository(db)

    def register(self, user_in: UserRegister) -> users:
        if self.repo.get_by_email(user_in.email):
            raise UserAlreadyExistsError()

        hashed = hash_password(user_in.password)
        user = self.repo.create(email=user_in.email, hashed_password=hashed)
        # -> déclencher ici l'envoi d'un email de vérification
        return user

    def authenticate(self, email: str, password: str) -> users:
        user = self.repo.get_by_email(email)
        if not user:
            raise InvalidCredentialsError()

        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            raise AccountLockedError()

        if not verify_password(password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + LOCK_DURATION
                user.failed_login_attempts = 0
            self.repo.save(user)
            raise InvalidCredentialsError()

        if not user.is_active:
            raise AccountInactiveError()

        user.failed_login_attempts = 0
        user.locked_until = None
        self.repo.save(user)
        return user

    def login(self, email: str, password: str) -> Token:
        user = self.authenticate(email, password)
        return Token(
            access_token=create_access_token(subject=user.email),
            refresh_token=create_refresh_token(subject=user.email),
        )

    def refresh_tokens(self, refresh_token: str) -> Token:
        payload = decode_token(refresh_token)
        if payload is None or payload.get("type") != "refresh":
            raise InvalidTokenError()

        user = self.repo.get_by_email(payload.get("sub"))
        if not user or not user.is_active:
            raise InvalidTokenError()

        return Token(
            access_token=create_access_token(subject=user.email),
            refresh_token=create_refresh_token(subject=user.email),  # rotation
        )

    def get_current_user_from_token(self, token: str) -> users:
        payload = decode_token(token)
        if payload is None or payload.get("type") != "access":
            raise InvalidTokenError()

        user = self.repo.get_by_email(payload.get("sub"))
        if not user or not user.is_active:
            raise InvalidTokenError()
        return user