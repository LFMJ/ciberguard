"""Configuración de la empresa guardada en la base de datos, con valores por defecto."""
from datetime import date

from flask import g, has_request_context

from .extensions import db
from .models import SLA_HOURS, Setting

DEFAULTS = {
    "company_name": "",
    "logo": "",  # nombre del archivo en instance/uploads
    "sla_alta": str(SLA_HOURS["alta"]),
    "sla_media": str(SLA_HOURS["media"]),
    "sla_baja": str(SLA_HOURS["baja"]),
    "incident_share": "60",  # % del riesgo global que aporta el riesgo por incidentes
    "extra_holidays": "",  # fechas AAAA-MM-DD, una por línea (festivos decretados que no calcula la ley)
    "telegram_token": "",
    "telegram_chat": "",
}


def all_settings():
    if has_request_context() and "settings" in g:
        return g.settings
    values = dict(DEFAULTS)
    try:
        values.update({s.key: s.value for s in Setting.query.all()})
    except Exception:  # tabla aún no creada
        db.session.rollback()
    if has_request_context():
        g.settings = values
    return values


def get(key):
    return all_settings().get(key, DEFAULTS.get(key, ""))


def set_many(values):
    for key, value in values.items():
        row = db.session.get(Setting, key) or Setting(key=key)
        row.value = value
        db.session.add(row)
    if has_request_context():
        g.pop("settings", None)


def sla_hours():
    out = {}
    for sev, default in SLA_HOURS.items():
        try:
            out[sev] = max(1, int(get(f"sla_{sev}")))
        except ValueError:
            out[sev] = default
    return out


def incident_share():
    try:
        return min(100, max(0, int(get("incident_share")))) / 100
    except ValueError:
        return 0.6


def extra_holidays():
    out = set()
    for line in get("extra_holidays").split():
        try:
            out.add(date.fromisoformat(line.strip()))
        except ValueError:
            pass
    return out
