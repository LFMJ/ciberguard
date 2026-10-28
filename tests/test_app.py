import re

import pytest

from app import create_app
from app.extensions import db
import io
import time

from app import totp
from app.models import AuditLog, Attachment, Incident, QuizAttempt, User, utcnow
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
    assert Incident.query.count() == 5


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
    # Incidentes: alta (10) + media (5) abiertos; el alta lleva 3 días sin atención (+5) → 20×3 = 60.
    # Madurez de la demo = 63 → global = 0.6×60 + 0.4×(100−63) = 51 → medio
    assert "<b>60</b><span>Riesgo por incidentes" in page
    assert 'data-score="51"' in page and "Riesgo medio" in page


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


# --- Mejoras para pymes ---------------------------------------------------

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 100


def test_report_shows_guide_and_saves_evidence(client):
    login(client, "laura")
    r = client.post("/reportar", data={
        "type": "malware", "title": "Abrí un adjunto raro", "description": "Se abrió una ventana negra y se cerró.",
        "personal_data": "no", "evidence": [(io.BytesIO(PNG), "captura.png"), (io.BytesIO(b"MZ fake exe"), "virus.png")],
    }, content_type="multipart/form-data")
    assert "nuevo=1" in r.headers["Location"]
    page = client.get(r.headers["Location"]).get_data(as_text=True)
    assert "Qué hacer ahora" in page and "Desconecta el equipo de la red" in page
    inc = Incident.query.filter_by(title="Abrí un adjunto raro").one()
    assert len(inc.attachments) == 1  # el ejecutable disfrazado se rechaza por su contenido
    att = inc.attachments[0]
    assert client.get(f"/adjuntos/{att.id}").status_code == 200
    client.post("/logout")
    login(client, "carlos")  # otro empleado no puede ver la evidencia
    assert client.get(f"/adjuntos/{att.id}").status_code == 404


def test_sla_first_response_and_overdue_filter(client):
    inc = Incident.query.filter_by(title="Correo falso del banco").one()
    assert inc.sla_state() == "vencido"  # alta, 3 días sin atender (plazo 4 h)
    login(client, "sofia")
    page = client.get("/gestion?sla=vencido").get_data(as_text=True)
    assert "Correo falso del banco" in page and "Adjunto .zip sospechoso" not in page
    client.post(f"/gestion/{inc.id}", data={"status": "en_revision", "severity": "alta", "notes": "", "assigned_to_id": ""})
    db.session.refresh(inc)
    assert inc.first_response_at is not None and inc.sla_state() == "incumplido"


def test_personal_data_sic_flow(client):
    login(client, "carlos")
    client.post("/reportar", data={"type": "acceso_indebido", "title": "Envié la base de clientes a quien no era",
                                   "description": "Mandé el Excel de clientes a un correo equivocado.", "personal_data": "si"})
    inc = Incident.query.filter_by(personal_data="si", sic_reported_at=None).one()
    client.post("/logout")
    login(client, "sofia")
    page = client.get(f"/incidentes/{inc.id}").get_data(as_text=True)
    assert "Ley 1581 de 2012" in page and "15 días hábiles" in page
    client.post(f"/gestion/{inc.id}", data={"status": "en_revision", "severity": "alta", "notes": "x",
                                           "personal_data": "si", "sic_reported_at": utcnow().date().isoformat()})
    db.session.refresh(inc)
    assert inc.sic_reported_at == utcnow().date() and not inc.needs_sic_report


def test_business_days():
    from datetime import date

    from app.compliance import add_business_days
    assert add_business_days(date(2026, 10, 30), 1) == date(2026, 11, 2)  # viernes + 1 hábil = lunes
    assert add_business_days(date(2026, 10, 28), 15) == date(2026, 11, 18)


def test_assessment_creates_plan(client):
    login(client, "carlos")
    assert client.get("/evaluacion").status_code == 403
    client.post("/logout")
    login(client, "ana")
    from app.content import QUESTION_IDS
    answers = dict.fromkeys(QUESTION_IDS, "si")
    assert client.post("/evaluacion/nueva", data={**answers, "mfa": ""}).status_code == 400  # incompleta
    answers["mfa"] = "no"
    r = client.post("/evaluacion/nueva", data=answers)
    assert r.status_code == 302
    page = client.get("/evaluacion").get_data(as_text=True)
    assert "Activa la verificación en dos pasos en el correo" in page
    assert "<b>92</b>" in page  # 35 de 38 puntos de peso (la doble verificación pesa 3) → 92


def test_quiz_scoring_and_team_view(client):
    from app.content import QUIZ
    login(client, "laura")
    data = {q["id"]: str(q["answer"]) for q in QUIZ}
    data[QUIZ[0]["id"]] = "0"
    page = client.post("/capacitacion", data=data).get_data(as_text=True)
    assert f"{len(QUIZ) - 1} de {len(QUIZ)}" in page
    assert QuizAttempt.query.filter_by(user_id=User.query.filter_by(username="laura").one().id).count() == 1
    assert client.get("/capacitacion/equipo").status_code == 403
    client.post("/logout")
    login(client, "sofia")
    assert "Laura Gómez" in client.get("/capacitacion/equipo").get_data(as_text=True)


def test_monthly_report(client):
    login(client, "ana")
    r = client.get("/reporte")
    assert r.status_code == 200 and "Reporte de ciberseguridad" in r.get_data(as_text=True)
    assert client.get("/reporte?mes=nada").status_code == 200


def _enable_2fa(client, user):
    client.post("/cuenta/seguridad", data={"action": "start"})
    with client.session_transaction() as s:
        secret = s["2fa_setup"]
    client.post("/cuenta/seguridad", data={"action": "confirm", "code": totp.now_code(secret)})
    db.session.refresh(user)
    assert user.totp_enabled
    return secret


def test_two_factor_login(client):
    sofia = User.query.filter_by(username="sofia").one()
    login(client, "sofia")
    secret = _enable_2fa(client, sofia)
    client.post("/logout")

    r = login(client, "sofia")
    assert r.headers["Location"].endswith("/login/verificar")
    assert client.get("/gestion").status_code == 302  # aún no ha iniciado sesión
    assert client.post("/login/verificar", data={"code": "000000"}).status_code == 401
    next_code = totp.now_code(secret, time.time() + 30)  # el código actual ya se usó al activar
    r = client.post("/login/verificar", data={"code": next_code})
    assert r.headers["Location"].endswith("/gestion")
    assert client.get("/gestion").status_code == 200
    # El mismo código no se puede reutilizar.
    client.post("/logout")
    login(client, "sofia")
    assert client.post("/login/verificar", data={"code": next_code}).status_code == 401


def test_admin_can_reset_2fa(client):
    sofia = User.query.filter_by(username="sofia").one()
    login(client, "sofia")
    _enable_2fa(client, sofia)
    client.post("/logout")
    login(client, "ana")
    client.post(f"/admin/usuarios/{sofia.id}", data={"action": "reset_2fa"})
    db.session.refresh(sofia)
    assert not sofia.totp_enabled


def test_schema_upgrade_adds_columns(tmp_path):
    import sqlite3

    from config import TestConfig as T
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(64), full_name VARCHAR(120), email VARCHAR(120),
          role VARCHAR(20), password_hash VARCHAR(255), is_active BOOLEAN, must_change_password BOOLEAN,
          failed_logins INTEGER, locked_until DATETIME, last_login_at DATETIME, created_at DATETIME);
        CREATE TABLE incidents (id INTEGER PRIMARY KEY, reporter_id INTEGER, type VARCHAR(30), title VARCHAR(150),
          description TEXT, severity VARCHAR(10), status VARCHAR(20), notes TEXT, assigned_to_id INTEGER,
          created_at DATETIME, updated_at DATETIME, resolved_at DATETIME);
        INSERT INTO incidents VALUES (1, 1, 'otro', 'Viejo', 'desc', 'baja', 'resuelto', '', NULL,
          '2026-01-01 00:00:00', '2026-01-02 00:00:00', '2026-01-02 00:00:00');
    """)
    con.commit()
    con.close()

    class Old(T):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{path}"

    app = create_app(Old)
    with app.app_context():
        inc = db.session.get(Incident, 1)
        assert inc.personal_data == "no_se" and inc.first_response_at is not None
        assert Attachment.query.count() == 0
        db.session.remove()
