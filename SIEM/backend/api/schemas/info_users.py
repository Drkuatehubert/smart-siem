from pydantic import BaseModel, field_validator
from fastapi import Form, UploadFile, File
from datetime import datetime
import re
import inspect


def as_form(cls):
    """Décorateur générique qui transforme un modèle Pydantic en dépendance FastAPI
    acceptant des champs Form(...) au lieu d'un body JSON."""
    new_params = [
        inspect.Parameter(
            field_name,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=Form(field_info.default) if not field_info.is_required() else Form(...),
            annotation=field_info.annotation,
        )
        for field_name, field_info in cls.model_fields.items()
    ]

    async def as_form_func(**data):
        return cls(**data)

    sig = inspect.Signature(new_params)
    as_form_func.__signature__ = sig
    cls.as_form = staticmethod(as_form_func)
    return cls


@as_form
class InfoUserCreate(BaseModel):
    profession: str | None = None
    telephone: str | None = None
    address: str | None = None
    description: str | None = None
    country: str | None = None
    nationality: str | None = None

    @field_validator("telephone")
    @classmethod
    def validate_telephone(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not re.match(r"^\+?[\d\s\-]{6,20}$", v):
            raise ValueError("Numéro de téléphone invalide")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str | None) -> str | None:
        if v and len(v) > 500:
            raise ValueError("La description ne doit pas dépasser 500 caractères")
        return v


@as_form
class InfoUserUpdate(BaseModel):
    profession: str | None = None
    telephone: str | None = None
    address: str | None = None
    description: str | None = None
    country: str | None = None
    nationality: str | None = None

    @field_validator("telephone")
    @classmethod
    def validate_telephone(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not re.match(r"^\+?[\d\s\-]{6,20}$", v):
            raise ValueError("Numéro de téléphone invalide")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str | None) -> str | None:
        if v and len(v) > 500:
            raise ValueError("La description ne doit pas dépasser 500 caractères")
        return v


class InfoUserOut(BaseModel):
    info_users_id: int
    users_id: int
    profession: str | None
    telephone: str | None
    address: str | None
    description: str | None
    country: str | None
    nationality: str | None
    picture: str | None
    created_at: datetime
    updated_at: datetime | None

    class Config:
        from_attributes = True