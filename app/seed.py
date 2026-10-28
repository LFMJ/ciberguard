"""Datos de demostración: los mismos personajes e incidentes del MVP."""
from datetime import timedelta

from .extensions import db
from .models import Incident, User, utcnow

DEMO_PASSWORD = "CiberGuard2026"

USERS = [
    ("ana", "Ana Torres", "admin"),
    ("carlos", "Carlos Pérez", "empleado"),
    ("laura", "Laura Gómez", "empleado"),
    ("sofia", "Sofía Ríos", "seguridad"),
]


def seed():
    out = []
    by_name = {}
    for username, name, role in USERS:
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, full_name=name, role=role, must_change_password=False)
            user.set_password(DEMO_PASSWORD)
            db.session.add(user)
            out.append(f"Usuario {username} ({role}) creado — contraseña: {DEMO_PASSWORD}")
        by_name[username] = user
    db.session.flush()

    if Incident.query.count() == 0:
        now = utcnow()
        sofia = by_name["sofia"]
        db.session.add_all([
            Incident(reporter=by_name["carlos"], type="phishing", title="Correo falso del banco",
                     description="Piden confirmar mi clave en un enlace extraño.", severity="alta",
                     status="reportado", created_at=now - timedelta(days=3)),
            Incident(reporter=by_name["laura"], type="malware", title="Adjunto .zip sospechoso",
                     description="Llegó de un proveedor que no conozco.", severity="media",
                     status="en_revision", notes="Equipo aislado.", assigned_to=sofia,
                     created_at=now - timedelta(days=1)),
            Incident(reporter=by_name["carlos"], type="contrasena", title="Contraseña en un post-it",
                     description="Vi una clave escrita en recepción.", severity="baja", status="resuelto",
                     notes="Clave cambiada.", assigned_to=sofia, created_at=now - timedelta(days=6),
                     resolved_at=now - timedelta(days=5)),
        ])
        for inc in list(db.session.new):
            if isinstance(inc, Incident):
                inc.updated_at = inc.resolved_at or inc.created_at
        out.append("3 incidentes de ejemplo creados.")
    db.session.commit()
    return out or ["Los datos de demostración ya existían."]
