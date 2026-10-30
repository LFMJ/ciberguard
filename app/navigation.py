"""Menú principal agrupado por rol.

Cada ítem: (endpoint, texto, ícono, endpoints que también lo marcan como activo).
"""
from .models import Incident

INCIDENTS_DETAIL = ("incidents.detail",)


def groups_for(user):
    role = user.role
    staff = role in ("seguridad", "admin")
    groups = []

    incidents = []
    if role == "seguridad":
        incidents.append(("incidents.manage", "Gestión", "inbox", INCIDENTS_DETAIL))
    elif role == "admin":
        incidents.append(("incidents.manage", "Incidentes", "inbox", INCIDENTS_DETAIL))
    incidents.append(("incidents.report", "Reportar incidente", "plus", () if staff else INCIDENTS_DETAIL))
    groups.append(("Incidentes", incidents))

    if staff:
        groups.append(("Riesgo", [
            ("incidents.dashboard", "Panel de riesgo", "gauge", ()),
            ("assessment.overview", "Autoevaluación", "check", ("assessment.new",)),
            ("incidents.monthly_report", "Reporte mensual", "file", ()),
        ]))
    prevention = [("training.quiz", "Capacitación", "cap", ("training.team",))]
    if staff:
        prevention.append(("incidents.poster", "Afiche con QR", "qr", ()))
    groups.append(("Prevención", prevention))

    if role == "admin":
        groups.append(("Administración", [
            ("admin.users", "Usuarios", "users", ("admin.edit_user",)),
            ("admin.audit_log", "Auditoría", "list", ()),
            ("admin.company", "Empresa", "building", ()),
        ]))
    return groups


def is_active(item, endpoint):
    ep, _label, _icon, also = item
    return endpoint == ep or endpoint in also


def pending_count(user):
    """Incidentes nuevos sin atender: se muestra como insignia a seguridad y administración."""
    if user.role not in ("seguridad", "admin"):
        return 0
    return Incident.query.filter_by(status="reportado").count()
