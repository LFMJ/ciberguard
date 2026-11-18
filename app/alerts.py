"""Alertas opcionales por Telegram para incidentes graves.

Por privacidad el mensaje no incluye título ni descripción: solo número, tipo, severidad y enlace.
Si Telegram no responde (por ejemplo, red restringida), el reporte se guarda igual y queda registrado el fallo.
"""
import json
import urllib.error
import urllib.parse
import urllib.request

from flask import current_app, url_for

from . import settings
from .models import SEVERITIES, TYPES

TIMEOUT_SECONDS = 6


def telegram_configured():
    return bool(settings.get("telegram_token") and settings.get("telegram_chat"))


def send_telegram(text):
    """Devuelve (ok, mensaje para la persona)."""
    if not telegram_configured():
        return False, "Configura el token del bot y el chat de Telegram."
    if current_app.config.get("TESTING"):
        return True, "Mensaje simulado (modo de pruebas)."
    token, chat = settings.get("telegram_token"), settings.get("telegram_chat")
    data = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "true"}).encode()
    try:
        with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=data,
                                    timeout=TIMEOUT_SECONDS) as resp:
            ok = json.loads(resp.read().decode() or "{}").get("ok", False)
        return (True, "Mensaje enviado a Telegram.") if ok else (False, "Telegram rechazó el mensaje. Revisa el chat.")
    except urllib.error.HTTPError as e:
        return False, f"Telegram respondió {e.code}: revisa el token del bot y el chat."
    except Exception:  # sin red, proxy, DNS…
        current_app.logger.warning("No se pudo contactar a Telegram", exc_info=True)
        return False, "No se pudo contactar a Telegram desde el servidor."


def incident_alert(inc):
    if not telegram_configured() or inc.severity != "alta":
        return None
    link = url_for("incidents.detail", incident_id=inc.id, _external=True)
    text = (f"🚨 CiberGuard: nuevo incidente #{inc.id} de severidad {SEVERITIES[inc.severity].lower()}\n"
            f"Tipo: {TYPES[inc.type]}\nRevísalo aquí: {link}")
    return send_telegram(text)
