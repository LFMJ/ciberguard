"""Recordatorios periódicos y comparación con el período anterior."""
from datetime import timedelta

from . import content, risk
from .models import Assessment, Incident, ReminderLog, utcnow


def reminders(now=None):
    """Lista de recordatorios con su estado: due (vence), last (última vez) y next (próxima fecha)."""
    now = now or utcnow()
    out = []
    for key, title, every, kind, why in content.REMINDERS:
        if kind == "auto" and key == "autoevaluacion":
            a = risk.latest_assessment()
            last = a.created_at if a else None
            pending = None
        elif kind == "auto" and key == "capacitacion":
            t = risk.training_summary(now)
            last, pending = None, t["total"] - t["trained"]
        else:
            log = ReminderLog.query.filter_by(key=key).order_by(ReminderLog.done_at.desc()).first()
            last, pending = (log.done_at if log else None), None
        if key == "capacitacion":
            due = bool(pending)
            nxt = None
        else:
            nxt = last + timedelta(days=every) if last else None
            due = last is None or nxt <= now
        out.append({"key": key, "title": title, "every": every, "kind": kind, "why": why, "last": last,
                    "next": nxt, "due": due, "pending": pending})
    return out


def risk_delta(days=30, now=None):
    """Riesgo global hoy y hace `days` días (con la autoevaluación vigente en cada fecha)."""
    now = now or utcnow()
    then = now - timedelta(days=days)
    incidents = Incident.query.all()

    def at(t):
        inc_score = risk.incident_score(incidents, t)[0]
        a = Assessment.query.filter(Assessment.created_at <= t).order_by(Assessment.created_at.desc()).first()
        return risk.combine(inc_score, a.score if a else None)

    current, before = at(now), at(then)
    return {"now": current, "before": before, "delta": current - before, "days": days}
