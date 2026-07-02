from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from api.config.setting import settings

# Configuration de l'URL de base de données
DATABASE_URL = (
    f"postgresql+psycopg2://"
    f"{settings.DATABASE_USER}:"
    f"{settings.DATABASE_PASSWORD}@"
    f"{settings.DATABASE_HOST}:"
    f"{settings.DATABASE_PORT}/"
    f"{settings.DATABASE_NAME}"
)

# Configuration de l'engine SQLAlchemy
engine = create_engine(
    DATABASE_URL, 
    echo=True
)

# Configuration de la session SQLAlchemy
session_local = sessionmaker(
    bind=engine, 
    autocommit=False, 
    autoflush=False
)

# Configuration de la base de données déclarative
class Base(DeclarativeBase):
    pass

def get_db():
    db = session_local()
    try:
        yield db
    finally:
        db.close()