"""Ley 1581 de 2012 (protección de datos personales, Colombia).

La SIC indica reportar los incidentes que afecten datos personales en el Registro Nacional de
Bases de Datos (RNBD) dentro de los 15 días hábiles siguientes a su detección.
Aquí se cuentan días hábiles de lunes a viernes; los festivos no se descuentan.
"""
from datetime import date, timedelta

from .models import utcnow

SIC_BUSINESS_DAYS = 15


def add_business_days(start, days):
    d = start
    while days > 0:
        d += timedelta(days=1)
        if d.weekday() < 5:
            days -= 1
    return d


def business_days_between(start, end):
    if end <= start:
        return -sum(1 for i in range(1, (start - end).days + 1) if (end + timedelta(days=i)).weekday() < 5)
    return sum(1 for i in range(1, (end - start).days + 1) if (start + timedelta(days=i)).weekday() < 5)


def sic_status(incident, today=None):
    today = today or utcnow().date()
    due = add_business_days(incident.created_at.date(), SIC_BUSINESS_DAYS)
    return {"due": due, "left": business_days_between(today, due), "overdue": today > due}


def as_date(value):
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None
