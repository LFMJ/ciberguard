import re
from functools import wraps

from flask import abort, request
from flask_login import current_user, login_required

from .extensions import db
from .models import AuditLog


def roles_required(*roles):
    """Restringe una vista a los roles indicados (403 para el resto)."""

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def client_ip():
    # PythonAnywhere pone la IP real del visitante en X-Real-IP.
    return (request.headers.get("X-Real-IP") or request.remote_addr or "")[:45]


def audit(action, detail="", user=None, incident=None):
    """Agrega una entrada a la bitácora. El commit lo hace quien llama."""
    if user is None and current_user and current_user.is_authenticated:
        user = current_user
    db.session.add(
        AuditLog(
            action=action,
            detail=detail,
            user_id=user.id if user else None,
            incident_id=incident.id if incident else None,
            ip=client_ip(),
        )
    )


def password_problems(raw, username=""):
    """Devuelve una lista de mensajes; vacía si la contraseña es aceptable."""
    problems = []
    if len(raw) < 10:
        problems.append("Debe tener al menos 10 caracteres.")
    if not re.search(r"[A-Za-zÁÉÍÓÚáéíóúÑñ]", raw) or not re.search(r"\d", raw):
        problems.append("Debe combinar letras y números.")
    if username and username.lower() in raw.lower():
        problems.append("No puede contener el nombre de usuario.")
    return problems
