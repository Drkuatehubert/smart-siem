# --- MODELES DE GESTIONS DES LOGS ---
from sqlalchemy.orm import Mapped, relationship, mapped_column
from sqlalchemy import String, Integer, ForeignKey, DateTime, func, Date, Time, Boolean
from api.config.database import Base
from api.models.users import users

# Création du modèle audit_logs pour gérer les audits des différents logs
class audit_log(Base) :
    # Nom de la table
    __tablename__ = "audit_log"
    
    audit_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    users_id : Mapped[int] = mapped_column(Integer, ForeignKey("users.users_id"))
    action : Mapped[str] = mapped_column(String, index=True, nullable=False)
    target_entity : Mapped[str] = mapped_column(String, nullable=True)
    target_id : Mapped[int] = mapped_column(Integer, nullable=True)
    ip_address : Mapped[str] = mapped_column(String[255], nullable=True)
    details : Mapped[str] = mapped_column(String, nullable=True)
    
    # Champ de traçabilité des événements
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True, server_default=func.now())
    
    user : Mapped["users"] = relationship("users", back_populates="audit_logs")
    
    
# Création du modèle sources pour gérer les sources des logs
class sources(Base) :
    # Nom de la table
    __tablename__ = "sources"
    
    sources_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name : Mapped[str] = mapped_column(String, nullable=False, index=True)
    type : Mapped[str] = mapped_column(String[200], nullable=False, index=True)
    adress_ip : Mapped[str] = mapped_column(String[255], nullable=True)
    environnement : Mapped[str] = mapped_column(String[200], nullable=True)
    status_collect : Mapped[str] = mapped_column(String, nullable=False, default=True)
    recept_final : Mapped[Date] = mapped_column(Date, nullable=True)
    
    # Champ de traçabilité des événements
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True, server_default=func.now())
    
    logs : Mapped["logs"] = relationship("logs", back_populates="sources")
    
    
# Création du modèle logs pour gérer le contenu des logs
class logs(Base) :
    # Nom de la table
    __tablename__ = "logs"
    
    logs_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    sources : Mapped[int] = mapped_column(Integer, ForeignKey("sources.sources_id"))
    timestamp : Mapped[Date] = mapped_column(Date, nullable=False)
    source_ip : Mapped[str] = mapped_column(String, nullable=False)
    log_type : Mapped[str] = mapped_column(String[255], nullable=False)
    severity : Mapped[str] = mapped_column(String, nullable=False)
    raw_message : Mapped[str] = mapped_column(String, nullable=False)
    normalized_fields : Mapped[str] = mapped_column(String, nullable=True)
    tags : Mapped[str] = mapped_column(String, nullable=True)
    
    # Traçabilité des logs
    is_flagged : Mapped[Boolean] = mapped_column(Boolean, default=False)
    archived : Mapped[Boolean] = mapped_column(Boolean, default=False)
    retention_expired : Mapped[DateTime] = mapped_column(DateTime, nullable=False)
    
    # Données supplémentaires 
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True, server_default=func.now()) 
    
    sources : Mapped["sources"] = relationship("sources", back_populates="logs")

# Création du modèles retention_policies pour gérer 
class retention_policies(Base) :
    # Nom de la table
    __tablename__= "rentention_policies"
    
    rent_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    perimetre : Mapped[str] = mapped_column(String, nullable=False)
    duree_jour : Mapped[int] = mapped_column(Integer, nullable=False)
    action_post_expiration : Mapped[str] = mapped_column(String, nullable=False)
    update_by : Mapped[int] = mapped_column(Integer, ForeignKey("users.users_id"))
    
    # Informations supplémentaires
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True, server_default=func.now()) 
    
    logs : Mapped["logs"] = relationship("logs", back_populates="rentention_policies")
    
# Création du modèle ueba_profiles pour gérer 
class ueba_profiles(Base):
    # Nom de la table
    __tablename__ = "ueba_profiles"
    
    ueba_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    entity_type : Mapped[str] = mapped_column(String, nullable=False)
    entity_ref : Mapped[str] = mapped_column(String, nullable=False)
    baseline : Mapped[str] = mapped_column(String, nullable=False)
    score_risque_courant : Mapped[int] = mapped_column(Integer, nullable=False)
    
    # informations supplémentaires pour la traçabilté
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now()) 
    
    logs : Mapped["logs"] = relationship("logs", back_populates="ueba_profiles")