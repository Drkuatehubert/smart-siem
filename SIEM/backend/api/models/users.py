# --- MODELES DE GESTIONS DES UTILISATEURS ---
from sqlalchemy.orm import Mapped, relationship, mapped_column
from sqlalchemy import String, Integer, ForeignKey, DateTime, func, Boolean
from api.config.database import Base

# Création du modèle Role pour gérer les différents rôle des utilisateurs
class roles(Base) :
    # Nom de la table
    __tablename__ = "roles"
    
    role_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name : Mapped[str] = mapped_column(String(100), unique=True)
    description : Mapped[str] = mapped_column(String, nullable=True)
    
    users : Mapped["users"] = relationship("users", back_populates="roles")
    
# Création du modèle permissions pour gérer les différentes autorisations des utilisateurs
class permissions(Base) :
    # Nom de la table
    __tablename__ = "permissions"
    
    permission_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name : Mapped[str] = mapped_column(String(100), unique=True)
    description : Mapped[str] = mapped_column(String, nullable=True)

# Création du modèle role_permissions pour gérer les différentes autorisations des rôles
class role_permissions(Base) :
    # Nom de la table
    __tablename__ = "role_permissions"
    
    role_permission_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    role_id : Mapped[int] = mapped_column(Integer, ForeignKey("roles.role_id"))
    permission_id : Mapped[int] = mapped_column(Integer, ForeignKey("permissions.permission_id"))
    
# Création du modèle users pour gérer les différents utilisateurs
class users(Base) :
    # Nom de la table
    __tablename__ = "users"
    
    users_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username : Mapped[str] = mapped_column(String(255))
    email : Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password : Mapped[str] = mapped_column(String(255), nullable=False)
    role_id : Mapped[int] = mapped_column(Integer, ForeignKey("roles.role_id"))
    
    # Champs permettant de gérer la traçabilté des utilisateurs
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True, server_default=func.now())
    is_active : Mapped[Boolean] = mapped_column(Boolean, default=True)
    
    roles : Mapped["roles"] = relationship("roles", back_populates="users")

# Création du modèle info_users pour gérer les informations supplémentaire des utilisateurs
class info_users(Base) :
    # Nom de la table
    __tablename__ = "info_users"
    
    info_users_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    users_id : Mapped[int] = mapped_column(Integer, ForeignKey("users.users_id"))
    profession : Mapped[str] = mapped_column(String(255), nullable=True)
    telephone : Mapped[str] = mapped_column(String(50), nullable=True)
    address : Mapped[str] = mapped_column(String(255), nullable=True)
    description : Mapped[str] = mapped_column(String(500), nullable=True)
    country : Mapped[str] = mapped_column(String(200), nullable=True)
    nationality : Mapped[str] = mapped_column(String(200), nullable=True)
    picture : Mapped[str | None] = mapped_column(String, nullable=True)
    
    # Champs permettant de gérer la traçabilté des utilisateurs
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True, server_default=func.now())
    
    user : Mapped["users"] = relationship("users", back_populates="info_users")
    
    
# Création du modèle refresh_tokens pour gérer les tokens de rafraîchissement des utilisateurs
from sqlalchemy import Boolean

class refresh_tokens(Base):
    __tablename__ = "refresh_tokens"

    token_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    jti: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    users_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.users_id"))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())