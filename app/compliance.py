"""Ley 1581 de 2012 (protección de datos personales, Colombia).

La SIC indica reportar los incidentes que afecten datos personales en el Registro Nacional de
Bases de Datos (RNBD) dentro de los 15 días hábiles siguientes a su detección.
Se cuentan días hábiles: lunes a viernes sin festivos de Colombia (calculados por ley) ni los festivos
adicionales que configure la empresa.
"""
from datetime import date, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import current_app

from . import holidays
from .models import utcnow

SIC_BUSINESS_DAYS = 15


def is_business_day(d, extra=frozenset()):
    return d.weekday() < 5 and not holidays.is_holiday(d) and d not in extra


def _extra():
    from .settings import extra_holidays

    try:
        return frozenset(extra_holidays())
    except RuntimeError:  # sin contexto de aplicación
        return frozenset()


def add_business_days(start, days, extra=None):
    extra = _extra() if extra is None else extra
    d = start
    while days > 0:
        d += timedelta(days=1)
        if is_business_day(d, extra):
            days -= 1
    return d


def business_days_between(start, end, extra=None):
    extra = _extra() if extra is None else extra
    lo, hi, sign = (start, end, 1) if end > start else (end, start, -1)
    return sign * sum(1 for i in range(1, (hi - lo).days + 1) if is_business_day(lo + timedelta(days=i), extra))


def local_date(utc_naive):
    """Fecha calendario en la zona horaria de la empresa (las fechas se guardan en UTC sin zona)."""
    tz = ZoneInfo(current_app.config["TIMEZONE"])
    return utc_naive.replace(tzinfo=timezone.utc).astimezone(tz).date()


def sic_status(incident, today=None):
    today = today or local_date(utcnow())
    due = add_business_days(local_date(incident.created_at), SIC_BUSINESS_DAYS)
    return {"due": due, "left": business_days_between(today, due), "overdue": today > due}


def as_date(value):
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None
