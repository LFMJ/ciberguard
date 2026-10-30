"""Aplicación instalable (PWA): manifiesto, service worker y página sin conexión.

El service worker solo guarda archivos estáticos y la página «sin conexión»; nunca páginas con sesión,
para que en un celular compartido no queden incidentes guardados.
"""
import json

from flask import Blueprint, Response, current_app, render_template, url_for

bp = Blueprint("pwa", __name__)


@bp.route("/manifest.webmanifest")
def manifest():
    icon = lambda name, size, purpose="any": {  # noqa: E731
        "src": url_for("static", filename=f"icons/{name}.png"), "sizes": f"{size}x{size}",
        "type": "image/png", "purpose": purpose}
    data = {
        "name": "CiberGuard", "short_name": "CiberGuard", "lang": "es",
        "description": "Reporta incidentes de ciberseguridad y sigue el riesgo de tu empresa.",
        "start_url": url_for("index"), "scope": "/", "display": "standalone",
        "background_color": "#0B1419", "theme_color": "#0B1419",
        "icons": [icon("icon-192", 192), icon("icon-512", 512), icon("icon-maskable-512", 512, "maskable")],
        "shortcuts": [{"name": "Reportar incidente", "url": url_for("incidents.report")}],
    }
    return Response(json.dumps(data, ensure_ascii=False), mimetype="application/manifest+json")


@bp.route("/sw.js")
def service_worker():
    v = current_app.jinja_env.globals["static_v"]
    precache = [url_for("pwa.offline"), url_for("static", filename="style.css", v=v),
                url_for("static", filename="app.js", v=v), url_for("static", filename="icons/icon-192.png")]
    js = render_template("sw.js", version=v, precache=json.dumps(precache), offline=json.dumps(url_for("pwa.offline")))
    resp = Response(js, mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@bp.route("/sin-conexion")
def offline():
    return render_template("offline.html")
