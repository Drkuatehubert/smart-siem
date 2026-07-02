import uuid
from pathlib import Path
from io import BytesIO
from fastapi import UploadFile
from PIL import Image as PILImage
from api.middlewares.exception import InvalidFileError

IMAGE_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp"}
MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 Mo

UPLOAD_DIR = Path("storage/images/profiles")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


async def save_profile_picture(file: UploadFile) -> str:
    if file.content_type not in IMAGE_CONTENT_TYPES:
        raise InvalidFileError("Format accepté : JPEG, PNG ou WEBP uniquement")

    contents = await file.read()
    if len(contents) > MAX_IMAGE_SIZE:
        raise InvalidFileError("Image trop volumineuse (max 5 Mo)")

    # Vérifie que c'est réellement une image, pas un fichier renommé
    try:
        pil_image = PILImage.open(BytesIO(contents))
        pil_image.verify()
        pil_image = PILImage.open(BytesIO(contents))
    except Exception:
        raise InvalidFileError("Le fichier n'est pas une image valide")

    pil_image.thumbnail((512, 512))  # une photo de profil n'a pas besoin d'être plus grande

    extension = pil_image.format.lower()
    filename = f"{uuid.uuid4().hex}.{extension}"
    filepath = UPLOAD_DIR / filename
    pil_image.save(filepath)

    return f"/storage/uploads/profile_pictures/{filename}"


def delete_old_picture(picture_path: str | None) -> None:
    if not picture_path:
        return
    import os
    real_path = picture_path.lstrip("/")
    if os.path.exists(real_path):
        os.remove(real_path)