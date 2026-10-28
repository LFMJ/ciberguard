"""Evidencia adjunta: valida el contenido real del archivo (no solo la extensión) y lo guarda con nombre aleatorio."""
import os
import secrets

from flask import current_app

from .extensions import db
from .models import ALLOWED_UPLOADS, Attachment

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_PER_INCIDENT = 5
MAGIC = {b"\x89PNG\r\n\x1a\n": "png", b"\xff\xd8\xff": "jpg", b"%PDF-": "pdf"}


def upload_dir():
    path = os.path.join(current_app.instance_path, "uploads")
    os.makedirs(path, exist_ok=True)
    return path


def _detect(head):
    for magic, ext in MAGIC.items():
        if head.startswith(magic):
            return ext
    return None


def save_files(files, incident, user):
    """Guarda los archivos válidos. Devuelve (guardados, errores)."""
    saved, errors = 0, []
    for f in files:
        if not f or not f.filename:
            continue
        if len(incident.attachments) + saved >= MAX_PER_INCIDENT:
            errors.append(f"Máximo {MAX_PER_INCIDENT} archivos por incidente.")
            break
        data = f.read(MAX_FILE_BYTES + 1)
        name = os.path.basename(f.filename)[:200]
        if len(data) > MAX_FILE_BYTES:
            errors.append(f"«{name}» supera 2 MB.")
            continue
        ext = _detect(data[:8])
        if not ext:
            errors.append(f"«{name}» no es una imagen PNG/JPG ni un PDF.")
            continue
        stored = secrets.token_hex(16) + "." + ext
        with open(os.path.join(upload_dir(), stored), "wb") as out:
            out.write(data)
        db.session.add(Attachment(incident=incident, uploader_id=user.id, original_name=name,
                                  stored_name=stored, mime=ALLOWED_UPLOADS[ext], size=len(data)))
        saved += 1
    return saved, errors
