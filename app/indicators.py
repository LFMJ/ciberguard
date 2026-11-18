"""Indicadores de compromiso (remitente, dominio, enlace) y detección de reportes repetidos."""
import re
from datetime import timedelta
from urllib.parse import urlparse

from .models import Incident, utcnow

CAMPAIGN_DAYS = 14
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# Dominios de correo gratuitos: compartirlos no indica una campaña.
FREE_MAIL = {"gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "live.com", "icloud.com", "yahoo.es",
             "hotmail.es", "outlook.es", "protonmail.com"}


def domain_of(sender, url):
    """Dominio del enlace o, si no hay, del correo del remitente; en minúsculas y sin «www.»."""
    host = ""
    if url:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = parsed.hostname or ""
    if not host and sender:
        m = EMAIL_RE.search(sender)
        host = m.group(1) if m else ""
    host = host.lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def sender_key(sender):
    m = EMAIL_RE.search(sender or "")
    if m:
        return m.group(0).lower()
    digits = re.sub(r"\D", "", sender or "")
    return digits if len(digits) >= 7 else ""


def related(inc, days=CAMPAIGN_DAYS):
    """Otros incidentes recientes con el mismo remitente o el mismo dominio (no gratuito)."""
    since = (inc.created_at or utcnow()) - timedelta(days=days)
    key, dom = sender_key(inc.ioc_sender), inc.ioc_domain
    if not key and (not dom or dom in FREE_MAIL):
        return []
    out = []
    for other in Incident.query.filter(Incident.id != inc.id, Incident.created_at >= since).all():
        if (key and sender_key(other.ioc_sender) == key) or (dom and dom not in FREE_MAIL and other.ioc_domain == dom):
            out.append(other)
    return sorted(out, key=lambda i: i.created_at)


def campaigns(incidents):
    """{id_incidente: tamaño del grupo} para los que comparten indicador con otros (incluido él mismo)."""
    groups = {}
    for i in incidents:
        for k in filter(None, [sender_key(i.ioc_sender), i.ioc_domain if i.ioc_domain not in FREE_MAIL else ""]):
            groups.setdefault(k, set()).add(i.id)
    sizes = {}
    for ids in groups.values():
        if len(ids) > 1:
            for x in ids:
                sizes[x] = max(sizes.get(x, 0), len(ids))
    return sizes
