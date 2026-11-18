"""Datos de demostración: los mismos personajes e incidentes del MVP."""
from datetime import timedelta

from .extensions import db
import json

from .content import QUESTION_IDS, maturity_score
from .models import Assessment, Incident, QuizAttempt, User, utcnow

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
                     created_at=now - timedelta(days=1), first_response_at=now - timedelta(days=1, hours=-2)),
            Incident(reporter=by_name["carlos"], type="contrasena", title="Contraseña en un post-it",
                     description="Vi una clave escrita en recepción.", severity="baja", status="resuelto",
                     notes="Clave cambiada.", assigned_to=sofia, created_at=now - timedelta(days=6),
                     first_response_at=now - timedelta(days=6, hours=-20), resolved_at=now - timedelta(days=5),
                     personal_data="no"),
            Incident(reporter=by_name["laura"], type="acceso_indebido", title="Portátil de ventas robado",
                     description="Me robaron el portátil en el bus. Tenía la base de clientes en Excel.",
                     severity="alta", status="resuelto", personal_data="si", assigned_to=sofia,
                     notes="Cuenta bloqueada y contraseñas cambiadas. El disco no estaba cifrado.",
                     created_at=now - timedelta(days=40), first_response_at=now - timedelta(days=40, hours=-2),
                     resolved_at=now - timedelta(days=30), sic_reported_at=(now - timedelta(days=33)).date()),
            Incident(reporter=by_name["carlos"], type="phishing", title="Factura falsa de proveedor",
                     description="Correo con supuesta factura en .zip.", severity="media", status="descartado",
                     notes="Correo bloqueado por el filtro; nadie lo abrió.", assigned_to=sofia,
                     created_at=now - timedelta(days=20), first_response_at=now - timedelta(days=19),
                     resolved_at=now - timedelta(days=10), personal_data="no"),
        ])
        for inc in list(db.session.new):
            if isinstance(inc, Incident):
                inc.updated_at = inc.resolved_at or inc.created_at
        out.append("5 incidentes de ejemplo creados.")

    if Assessment.query.count() == 0:
        answers = dict.fromkeys(QUESTION_IDS, "si")
        answers.update({"cifrado": "no", "copias": "parcial", "restauracion": "no", "mfa": "parcial",
                        "inventario_equipos": "parcial", "proveedores": "no_se", "admin_separado": "no",
                        "capacitacion": "no"})
        db.session.add(Assessment(user_id=by_name["sofia"].id, answers_json=json.dumps(answers),
                                  score=maturity_score(answers), created_at=utcnow() - timedelta(days=2)))
        db.session.add_all([
            QuizAttempt(user_id=by_name["carlos"].id, correct=6, total=8, created_at=utcnow() - timedelta(days=10)),
            QuizAttempt(user_id=by_name["sofia"].id, correct=8, total=8, created_at=utcnow() - timedelta(days=12)),
        ])
        out.append("Autoevaluación y resultados de capacitación de ejemplo creados.")
    db.session.commit()
    return out or ["Los datos de demostración ya existían."]
