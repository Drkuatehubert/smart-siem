# --- MODELES DE GESTIONS DES ALERTS ---
from sqlalchemy.orm import Mapped, relationship, mapped_column
from sqlalchemy import String, Integer, ForeignKey, DateTime, func, Date, Time, Boolean
from api.config.database import Base
from api.models.users import users

# Création du modèles correlation_rules pour gérer les règle de corrélation utilisées par le moteur de détection
class correlation_rules(Base) :
    # Nom de la table 
    __tablename__ = "correlation_rules"
    
    correlation_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name : Mapped[str] = mapped_column(String[200], nullable=False)
    type : Mapped[str] = mapped_column(String, nullable=False)
    condition : Mapped[str] = mapped_column(String, nullable=False)
    fenetre_temporelle_s : Mapped[int] = mapped_column(Integer, nullable=False)
    mitre_tactic : Mapped[str] = mapped_column(String, nullable=True)
    niveau_alerte : Mapped[str] = mapped_column(String[200], nullable=False)
    active : Mapped[Boolean] = mapped_column(Boolean, nullable=False, default=True)
    description : Mapped[str] = mapped_column(String, nullable=True)
        
    # Informations supplémentaire pour la traçabilité
    created_by : Mapped[int] = mapped_column(Integer, ForeignKey("users.users_id"))
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True, server_default=func.now())
        
    alerts : Mapped["alerts"] = relationship("alerts", back_populates="correlation_rules")
        
# Création du modèle alerts pour gérer pour gérer 
class alerts(Base) :
    # Nom de la table
    __tablename__ = "alerts"
    
    alerts_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    correlation_id : Mapped[int] = mapped_column(Integer, ForeignKey("correlation_rules.correlation_id"))
    assigned_to : Mapped[int] = mapped_column(Integer, ForeignKey("users.users_id"))
    log_refs : Mapped[str] = mapped_column(String, nullable=False, index=True)
    niveau : Mapped[str] = mapped_column(String[200], nullable=False)
    statut : Mapped[str] = mapped_column(String, nullable=False, default="ouvert")
    score_risque : Mapped[int] = mapped_column(Integer, nullable=True)
    commentaire : Mapped[str] = mapped_column(String, nullable=True)
    
    # Informations supplémentaire pour la traçabilté
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    correlation_rules : Mapped["correlation_rules"] = relationship("correlation_rules", back_populates="alerts")


# création du modèle report pour gérer
class report(Base) : 
    # Nom de la table
    __tablename__ = "report"
    
    report_id : Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    genered_by : Mapped[int] = mapped_column(Integer, ForeignKey("users.users_id"))
    type : Mapped[str] = mapped_column(String[50], nullable=False)
    format : Mapped[str] = mapped_column(String[50], nullable=False)
    debut : Mapped[Date] = mapped_column(Date, nullable=False)
    fin : Mapped[Date] = mapped_column(Date, nullable=True)
    path : Mapped[str] = mapped_column(String[200], nullable=False)
    
    # Informations supplémentaire pour la traçabilité
    updated_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at : Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    alerts : Mapped["users"] = relationship("users", back_populates="report")
    