"""Notificaciones dentro de la aplicación (la campana del menú)."""
from flask_login import current_user

from .extensions import db
from .models import SEVERITIES, Notification, User, utcnow  # noqa: F401  (Notification se usa desde otros módulos)


def _security_team():
    return User.query.filter_by(role="seguridad", is_active_flag=True).all()


def _add(users, inc, text):
    for u in {u.id: u for u in users}.values():
        if current_user.is_authenticated and u.id == current_user.id:
            continue  # nadie se notifica a sí mismo
        db.session.add(Notification(user_id=u.id, incident_id=inc.id if inc else None, text=text[:300]))


def new_incident(inc):
    _add(_security_team(), inc, f"Nuevo incidente #{inc.id} de severidad {SEVERITIES[inc.severity].lower()}: {inc.title}")


def incident_updated(inc, changes):
    _add([inc.reporter], inc, f"Tu reporte #{inc.id} se actualizó: {changes}")


def new_comment(inc, author):
    if author.id == inc.reporter_id:
        targets = [inc.assigned_to] if inc.assigned_to else _security_team()
        who = "La persona que reportó" if inc.anonymous else author.full_name
    else:
        targets = [inc.reporter]
        who = "Seguridad"
    _add(targets, inc, f"{who} escribió en el incidente #{inc.id}")


def unread_count(user):
    return Notification.query.filter_by(user_id=user.id, read_at=None).count()


def mark_incident_read(user, inc):
    Notification.query.filter_by(user_id=user.id, incident_id=inc.id, read_at=None).update({"read_at": utcnow()})
