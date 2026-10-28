"""Cálculo del nivel de riesgo (misma fórmula que la demo MVP)."""
from datetime import timedelta

from .models import CLOSED_STATES, OPEN_STATES, STATES, TYPES, Incident, utcnow

WEIGHTS = {"alta": 10, "media": 5, "baja": 2}
STALE_HOURS = 48

MESSAGES = {
    "bajo": ("Riesgo bajo", "Todo está bajo control. Sigue capacitando a tu equipo y revisando los reportes nuevos."),
    "medio": ("Riesgo medio", "Hay incidentes abiertos. Pide al encargado de seguridad que los revise esta semana."),
    "alto": ("Riesgo alto", "Hay incidentes graves o sin atender. Prioriza su revisión hoy mismo."),
}


def compute():
    incidents = Incident.query.all()
    now = utcnow()
    open_ = [i for i in incidents if i.status in OPEN_STATES]
    stale = [i for i in open_ if i.status == "reportado" and now - i.created_at > timedelta(hours=STALE_HOURS)]
    score = min(100, (sum(WEIGHTS.get(i.severity, 5) for i in open_) + len(stale) * 5) * 3)
    level = "bajo" if score < 25 else "medio" if score < 60 else "alto"

    resolved = [i for i in incidents if i.status in CLOSED_STATES and i.resolved_at]
    avg_hours = (
        round(sum((i.resolved_at - i.created_at).total_seconds() for i in resolved) / len(resolved) / 3600)
        if resolved
        else None
    )

    def counts(attr, labels):
        rows = [(labels[k], sum(1 for i in incidents if getattr(i, attr) == k)) for k in labels]
        top = max([n for _, n in rows] + [1])
        return [(label, n, round(n / top * 100)) for label, n in rows]

    return {
        "score": score,
        "level": level,
        "title": MESSAGES[level][0],
        "message": MESSAGES[level][1],
        "open": len(open_),
        "stale": len(stale),
        "total": len(incidents),
        "avg_hours": avg_hours,
        "by_status": counts("status", STATES),
        "by_type": counts("type", TYPES),
    }
