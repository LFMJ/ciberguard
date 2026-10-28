"""Nivel de riesgo de la organización.

Riesgo por incidentes (misma idea de la demo MVP):
    (alta×10 + media×5 + baja×2 de los abiertos + 5 por cada uno fuera del tiempo de atención) × 3, máx. 100
Riesgo global, si hay autoevaluación:
    60 % riesgo por incidentes + 40 % brecha de madurez (100 − puntaje de madurez)
"""
from datetime import datetime, timedelta

from . import content
from .models import (
    CLOSED_STATES, OPEN_STATES, SEVERITIES, STATES, TYPES, Assessment, Incident, QuizAttempt, User, utcnow,
)

WEIGHTS = {"alta": 10, "media": 5, "baja": 2}
INCIDENT_SHARE = 0.6
TRAINING_WINDOW_DAYS = 90

MESSAGES = {
    "bajo": ("Riesgo bajo", "Todo está bajo control. Sigue capacitando a tu equipo y revisando los reportes nuevos."),
    "medio": ("Riesgo medio", "Hay puntos por atender. Revisa los incidentes abiertos y el plan de acción de la autoevaluación."),
    "alto": ("Riesgo alto", "Hay incidentes graves, atrasados o brechas importantes. Prioriza su revisión hoy mismo."),
}


def level(score):
    return "bajo" if score < 25 else "medio" if score < 60 else "alto"


def _open_at(i, t):
    return i.created_at <= t and (i.resolved_at is None or i.resolved_at > t) and (
        i.resolved_at is not None or i.status in OPEN_STATES
    )


def _overdue_at(i, t):
    return _open_at(i, t) and (i.first_response_at is None or i.first_response_at > t) and t > i.sla_due


def incident_score(incidents, t):
    open_ = [i for i in incidents if _open_at(i, t)]
    overdue = [i for i in open_ if _overdue_at(i, t)]
    return min(100, (sum(WEIGHTS.get(i.severity, 5) for i in open_) + len(overdue) * 5) * 3), open_, overdue


def combine(inc_score, maturity):
    if maturity is None:
        return inc_score
    return round(INCIDENT_SHARE * inc_score + (1 - INCIDENT_SHARE) * (100 - maturity))


def sla_summary(incidents, now):
    states = [i.sla_state(now) for i in incidents if i.status != "descartado" or i.first_response_at]
    measured = [s for s in states if s != "en_plazo"]
    met = sum(1 for s in measured if s == "cumplido")
    return {"pct": round(met / len(measured) * 100) if measured else None, "measured": len(measured), "met": met}


def training_summary(now):
    since = now - timedelta(days=TRAINING_WINDOW_DAYS)
    users = User.query.filter_by(is_active_flag=True).order_by(User.full_name).all()
    rows = []
    for u in users:
        last = QuizAttempt.query.filter_by(user_id=u.id).order_by(QuizAttempt.created_at.desc()).first()
        rows.append({"user": u, "last": last, "current": bool(last and last.created_at >= since)})
    trained = [r for r in rows if r["current"]]
    return {
        "rows": rows,
        "coverage": round(len(trained) / len(rows) * 100) if rows else 0,
        "avg": round(sum(r["last"].pct for r in trained) / len(trained)) if trained else None,
        "trained": len(trained),
        "total": len(rows),
    }


def latest_assessment():
    return Assessment.query.order_by(Assessment.created_at.desc(), Assessment.id.desc()).first()


def trend(incidents, now, weeks=8):
    """Riesgo por incidentes al cierre de cada una de las últimas semanas (la severidad usada es la actual)."""
    points = []
    for k in range(weeks - 1, -1, -1):
        t = now - timedelta(weeks=k)
        points.append({"t": t, "score": incident_score(incidents, t)[0]})
    return points


def compute():
    now = utcnow()
    incidents = Incident.query.all()
    inc_score, open_, overdue = incident_score(incidents, now)
    a = latest_assessment()
    maturity = a.score if a else None
    score = combine(inc_score, maturity)
    lv = level(score)

    resolved = [i for i in incidents if i.status in CLOSED_STATES and i.resolved_at]
    avg_hours = (
        round(sum((i.resolved_at - i.created_at).total_seconds() for i in resolved) / len(resolved) / 3600)
        if resolved else None
    )

    def counts(attr, labels):
        rows = [(labels[k], sum(1 for i in incidents if getattr(i, attr) == k)) for k in labels]
        top = max([n for _, n in rows] + [1])
        return [(label, n, round(n / top * 100)) for label, n in rows]

    return {
        "score": score,
        "level": lv,
        "title": MESSAGES[lv][0],
        "message": MESSAGES[lv][1],
        "incident_score": inc_score,
        "maturity": maturity,
        "maturity_level": content.maturity_level(maturity) if maturity is not None else None,
        "assessment": a,
        "plan": content.action_plan(a.answers)[:3] if a else [],
        # Lo primero que hay que mirar: vencidos, luego por severidad y antigüedad.
        "attention": sorted(open_, key=lambda i: (i.sla_state(now) != "vencido", -WEIGHTS.get(i.severity, 5),
                                                  i.created_at))[:3],
        "open": len(open_),
        "overdue": len(overdue),
        "total": len(incidents),
        "avg_hours": avg_hours,
        "sla": sla_summary(incidents, now),
        "sic_pending": sum(1 for i in incidents if i.needs_sic_report),
        "training": training_summary(now),
        "trend": trend(incidents, now),
        "by_status": counts("status", STATES),
        "by_type": counts("type", TYPES),
    }


def month_summary(year, month):
    start = datetime(year, month, 1)
    end = datetime(year + (month == 12), month % 12 + 1, 1)
    now = min(utcnow(), end)
    all_incidents = Incident.query.all()
    inc = [i for i in all_incidents if start <= i.created_at < end]
    closed = [i for i in all_incidents if i.resolved_at and start <= i.resolved_at < end]
    avg = (
        round(sum((i.resolved_at - i.created_at).total_seconds() for i in closed) / len(closed) / 3600)
        if closed else None
    )
    a = Assessment.query.filter(Assessment.created_at < end).order_by(Assessment.created_at.desc()).first()
    attempts = QuizAttempt.query.filter(QuizAttempt.created_at >= start, QuizAttempt.created_at < end).all()
    inc_score_end = incident_score(all_incidents, now)[0]
    return {
        "start": start,
        "end": end,
        "reported": len(inc),
        "closed": len(closed),
        "avg_hours": avg,
        "by_type": [(TYPES[k], sum(1 for i in inc if i.type == k)) for k in TYPES],
        "by_severity": [(SEVERITIES[k], sum(1 for i in inc if i.severity == k)) for k in SEVERITIES],
        "sla": sla_summary(inc, now),
        "personal_data": [i for i in inc if i.personal_data == "si"],
        "open_at_end": len(incident_score(all_incidents, now)[1]),
        "score_end": combine(inc_score_end, a.score if a else None),
        "assessment": a,
        "plan": content.action_plan(a.answers)[:5] if a else [],
        "attempts": len(attempts),
        "people_trained": len({x.user_id for x in attempts}),
        "quiz_avg": round(sum(x.pct for x in attempts) / len(attempts)) if attempts else None,
        "highlights": sorted(inc, key=lambda i: (-WEIGHTS[i.severity], i.created_at))[:5],
    }
