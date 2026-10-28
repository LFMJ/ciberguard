import re

import pytest

from app import create_app
from app.extensions import db
from app.models import AuditLog, Incident, User
from app.seed import DEMO_PASSWORD, seed
from config import TestConfig


@pytest.fixture()
def app():
    app = create_app(TestConfig)
    with app.app_context():
        seed()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username, password=DEMO_PASSWORD):
    return client.post("/login", data={"username": username, "password": password})


def test_login_redirects_by_role(client):
    assert login(client, "carlos").headers["Location"].endswith("/reportar")
    client.post("/logout")
    assert login(client, "sofia").headers["Location"].endswith("/gestion")
    client.post("/logout")
    assert login(client, "ana").headers["Location"].endswith("/panel")


def test_protected_pages_require_login(client):
    for url in ("/reportar", "/gestion", "/panel", "/admin/usuarios", "/admin/auditoria"):
        assert client.get(url).status_code == 302


def test_wrong_password_and_lockout(client, app):
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        assert login(client, "carlos", "mala-clave-123").status_code == 401
    # Bloqueada incluso con la clave correcta.
    assert login(client, "carlos").status_code == 429
    assert db.session.query(User).filter_by(username="carlos").one().is_locked()


def test_unknown_user_same_message(client):
    r = login(client, "noexiste", "x")
    assert r.status_code == 401 and "Usuario o contraseña incorrectos" in r.get_data(as_text=True)


@pytest.mark.parametrize(
    "user,allowed,forbidden",
    [
        ("carlos", ["/reportar"], ["/gestion", "/panel", "/admin/usuarios", "/admin/auditoria"]),
        ("sofia", ["/reportar", "/gestion", "/panel"], ["/admin/usuarios", "/admin/auditoria"]),
        ("ana", ["/reportar", "/gestion", "/panel", "/admin/usuarios", "/admin/auditoria"], []),
    ],
)
def test_role_permissions(client, user, allowed, forbidden):
    login(client, user)
    for url in allowed:
        assert client.get(url).status_code == 200, url
    for url in forbidden:
        assert client.get(url).status_code == 403, url


def test_employee_reports_and_sees_only_own(client):
    login(client, "laura")
    r = client.post("/reportar", data={"type": "phishing", "title": "Correo raro", "description": "Me pidieron la clave del correo."})
    assert r.status_code == 302
    page = client.get("/reportar").get_data(as_text=True)
    assert "Correo raro" in page and "Correo falso del banco" not in page  # el de Carlos no aparece
    carlos_inc = Incident.query.filter_by(title="Correo falso del banco").one()
    assert client.get(f"/incidentes/{carlos_inc.id}").status_code == 404


def test_report_validation(client):
    login(client, "laura")
    r = client.post("/reportar", data={"type": "phishing", "title": "abc", "description": "corto"})
    assert r.status_code == 400
    assert Incident.query.count() == 3


def test_security_updates_incident_and_audits(client):
    inc = Incident.query.filter_by(title="Correo falso del banco").one()
    sofia = User.query.filter_by(username="sofia").one()
    login(client, "sofia")
    r = client.post(f"/gestion/{inc.id}", data={
        "status": "resuelto", "severity": "alta", "notes": "Dominio bloqueado.", "assigned_to_id": str(sofia.id),
        "next": "//evil.example",
    })
    assert r.status_code == 302 and r.headers["Location"].endswith("/gestion")  # sin redirección abierta
    db.session.refresh(inc)
    assert inc.status == "resuelto" and inc.resolved_at and inc.assigned_to_id == sofia.id
    assert AuditLog.query.filter_by(incident_id=inc.id, action="incidente_actualizado").count() == 1


def test_admin_cannot_edit_incidents(client):
    inc = Incident.query.first()
    login(client, "ana")
    assert client.post(f"/gestion/{inc.id}", data={"status": "resuelto", "severity": "baja"}).status_code == 403


def test_admin_creates_user_with_forced_password_change(client):
    login(client, "ana")
    r = client.post("/admin/usuarios", data={"username": "pedro", "full_name": "Pedro Ruiz", "email": "", "role": "empleado"})
    temp = re.search(r"<code>([^<]+)</code>", r.get_data(as_text=True)).group(1)
    client.post("/logout")

    login(client, "pedro", temp)
    assert client.get("/reportar").headers["Location"].endswith("/cuenta/contrasena")
    r = client.post("/cuenta/contrasena", data={"current": temp, "new": "OtraClave2026x", "confirm": "OtraClave2026x"})
    assert r.status_code == 302
    assert client.get("/reportar").status_code == 200


def test_password_policy(client):
    login(client, "carlos")
    r = client.post("/cuenta/contrasena", data={"current": DEMO_PASSWORD, "new": "corta", "confirm": "corta"})
    assert r.status_code == 400


def test_admin_cannot_demote_self(client):
    ana = User.query.filter_by(username="ana").one()
    login(client, "ana")
    client.post(f"/admin/usuarios/{ana.id}", data={"action": "save", "full_name": "Ana Torres", "role": "empleado", "active": "1"})
    db.session.refresh(ana)
    assert ana.role == "admin"


def test_deactivated_user_cannot_login(client):
    carlos = User.query.filter_by(username="carlos").one()
    login(client, "ana")
    client.post(f"/admin/usuarios/{carlos.id}", data={"action": "save", "full_name": "Carlos Pérez", "role": "empleado", "active": "0"})
    client.post("/logout")
    assert login(client, "carlos").status_code == 401


def test_dashboard_score(client):
    login(client, "sofia")
    page = client.get("/panel").get_data(as_text=True)
    # Abiertos: alta (10) + media (5); uno "reportado" con 3 días (+5) → (20)×3 = 60 → alto
    assert 'data-score="60"' in page and "Riesgo alto" in page


def test_csv_export_escapes_formulas(client):
    login(client, "laura")
    client.post("/reportar", data={"type": "otro", "title": "=HYPERLINK(1)", "description": "prueba de fórmula"})
    client.post("/logout")
    login(client, "sofia")
    csv = client.get("/gestion/exportar.csv").get_data(as_text=True)
    assert "'=HYPERLINK(1)" in csv


def test_security_headers(client):
    r = client.get("/login")
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"


def test_csrf_enforced_when_enabled():
    class CSRFOn(TestConfig):
        WTF_CSRF_ENABLED = True

    app = create_app(CSRFOn)
    with app.app_context():
        seed()
        assert app.test_client().post("/login", data={"username": "ana", "password": DEMO_PASSWORD}).status_code == 400
