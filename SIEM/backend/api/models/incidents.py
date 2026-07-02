# --- MODELES DE GESTIONS DES INCIDENTS ---
from sqlalchemy.orm import Mapped, relationship, mapped_column
from sqlalchemy import String, Integer, ForeignKey, DateTime, func, Date, Boolean
from api.config.database import Base

from api.models.users import users
from api.models.alerts import alerts
from api.models.alerts import correlation_rules


# Création du modèle incidents pour gérer la suivie formelle d'un incident de securite, pouvant regrouper une ou plusieurs alertes
class incidents(Base) :
    # Nom de la table
    __tablename__ = "incidents"
    
    incidents_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner : Mapped[int] = mapped_column(Integer, ForeignKey("users.users_id"))
    titre : Mapped[str] = mapped_column(String, nullable=False, index=True)
    description : Mapped[str] = mapped_column(String, nullable=True)
    statut : Mapped[str] = mapped_column(String[200], nullable=False)
    priorite : Mapped[str] = mapped_column(String[200], nullable=False)
    date_ouverture : Mapped[Date] = mapped_column(Date, nullable=False)
    date_fermeture : Mapped[Date] = mapped_column(Date, nullable=True)
    
    # Informations supplémentaire pour la traçabilté
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    alerts : Mapped["alerts"] = relationship("alerts", back_populates="incidents")


# Création du modèle playbook_execution pour gérer le catalogue des playbooks de reponse automatisee (module SOAR simplifie)
class playbook(Base) :
    # Nom de la table
    __tablename__ = "playbook"
    
    playbook_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    triggers_rules_id : Mapped[int] = mapped_column(Integer, ForeignKey("correlation_rules.correlation_id"))
    action : Mapped[str] = mapped_column(String, nullable=False)
    validation_requise : Mapped[Boolean] = mapped_column(Boolean, nullable=False, default=True)
    description : Mapped[str] = mapped_column(String, nullable=True)
    
    # Informations supplémentaire pour la traçabilté
    actif : Mapped[Boolean] = mapped_column(Boolean, nullable=False, default=True)
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    correlation_rules : Mapped["correlation_rules"] = relationship("correlation_rules", back_populates="playbook")


# Création du modèle playbook pour gérer l'historique d'execution des playbooks, indispensable pour l'audit et la tracabilite des actions correctives
class playbook_execution(Base) :
    # Nom de la table
    __tablename__ = "playbook_execution"
    
    execution_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    playbook_id : Mapped[int] = mapped_column(Integer, ForeignKey("playbook.playbook_id"))
    incidents_id : Mapped[int] = mapped_column(Integer, ForeignKey("incidents.incidents_id"))
    executed_by : Mapped[int] = mapped_column(Integer, ForeignKey("users.users_id"))
    action : Mapped[str] = mapped_column(String[50], nullable=False)
    log_executed : Mapped[str] = mapped_column(String, nullable=True)
    execute_date : Mapped[Boolean] = mapped_column(Boolean, nullable=True)
    
    # Informations supplémentaire pour la traçabilté
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    playbook : Mapped["playbook"] = relationship("playbook", back_populates="playbook_execution")
    