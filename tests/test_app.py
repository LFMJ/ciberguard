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
    client.post("/logout")
    login(client, "ana")  # la administración de cuentas tampoco
    assert client.get(f"/adjuntos/{att.id}").status_code == 404
    assert "solo los ven quien reportó" in client.get(f"/incidentes/{inc.id}").get_data(as_text=True)
    client.post("/logout")
    login(client, "sofia")
    assert client.get(f"/adjuntos/{att.id}").status_code == 200


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


def test_sic_deadline_uses_local_date(app):
    from datetime import date, datetime

    from app.compliance import sic_status
    # Martes 27-oct-2026 a las 8 p. m. en Bogotá = miércoles 28-oct 01:00 UTC.
    inc = Incident(created_at=datetime(2026, 10, 28, 1, 0))
    st = sic_status(inc, today=date(2026, 10, 27))
    # 15 hábiles desde el martes (no desde el miércoles), sin contar los festivos del 2 y el 16 de noviembre.
    assert st["due"] == date(2026, 11, 19)
    assert st["left"] == 15


def test_business_days():
    from datetime import date

    from app.compliance import add_business_days
    assert add_business_days(date(2026, 10, 23), 1) == date(2026, 10, 26)  # viernes + 1 hábil = lunes
    # El lunes 2 y el lunes 16 de noviembre de 2026 son festivos (Todos los Santos y Cartagena).
    assert add_business_days(date(2026, 10, 30), 1) == date(2026, 11, 3)
    assert add_business_days(date(2026, 10, 28), 15) == date(2026, 11, 20)
    assert add_business_days(date(2026, 10, 28), 15, extra=frozenset({date(2026, 11, 20)})) == date(2026, 11, 23)


def test_colombian_holidays():
    from datetime import date

    from app.holidays import colombia, easter
    assert easter(2026) == date(2026, 4, 5) and easter(2027) == date(2027, 3, 28) and easter(2025) == date(2025, 4, 20)
    days = [d for d, _ in colombia(2026)]
    assert len(days) == 18
    for d in ["2026-01-12", "2026-03-23", "2026-04-02", "2026-04-03", "2026-05-18", "2026-06-08",
              "2026-06-15", "2026-06-29", "2026-08-17", "2026-10-12", "2026-11-02", "2026-11-16"]:
        assert date.fromisoformat(d) in days, d


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


# --- Configuración de la empresa ------------------------------------------

def test_company_settings(client):
    login(client, "sofia")
    assert client.get("/admin/empresa").status_code == 403
    client.post("/logout")
    login(client, "ana")
    page = client.get("/admin/empresa").get_data(as_text=True)
    assert "Todos los Santos" in page  # festivos calculados visibles
    base = {"company_name": "Distribuciones Andinas", "sla_alta": "2", "sla_media": "12", "sla_baja": "48",
            "incident_share": "50", "extra_holidays": "", "telegram_chat": "", "telegram_token": ""}
    # Plazos desordenados o fechas inválidas se rechazan
    client.post("/admin/empresa", data={**base, "sla_alta": "30"})
    client.post("/admin/empresa", data={**base, "extra_holidays": "29/10/2026"})
    from app import settings
    assert settings.get("sla_alta") == "4"
    client.post("/admin/empresa", data={**base, "extra_holidays": "2026-11-20",
                                       "logo": (io.BytesIO(PNG), "logo.png")}, content_type="multipart/form-data")
    assert settings.sla_hours() == {"alta": 2, "media": 12, "baja": 48}
    assert "Distribuciones Andinas" in client.get("/panel").get_data(as_text=True)
    assert client.get("/admin/logo").status_code == 200
    inc = Incident.query.filter_by(title="Correo falso del banco").one()
    assert inc.sla_due == inc.created_at + __import__("datetime").timedelta(hours=2)
    # Con peso 50 %: 0,5 × 60 + 0,5 × (100 − 63) = 48,5 → 48 (redondeo bancario de Python)
    assert 'data-score="48"' in client.get("/panel").get_data(as_text=True)


# --- Reporte guiado, anonimato, conversación y respuesta -------------------

def _report(client, **extra):
    data = {"type": "phishing", "title": "Correo de la DIAN falso", "description": "Pedía actualizar datos en un enlace.",
            "personal_data": "no"}
    data.update(extra)
    r = client.post("/reportar", data=data)
    assert r.status_code == 302, r.get_data(as_text=True)[:300]
    return Incident.query.order_by(Incident.id.desc()).first()


def test_guided_answers_suggest_severity(client):
    login(client, "laura")
    inc = _report(client, g_phishing_clic="si", g_phishing_clave="no", g_phishing_banco="no", g_phishing_respondio="no")
    assert inc.severity == "media" and inc.guided["clic"] == "si"
    inc = _report(client, g_phishing_clave="si")
    assert inc.severity == "alta" and inc.suggested_severity == "alta"
    inc = _report(client, **{f"g_phishing_{q}": "no" for q in ("clic", "clave", "banco", "respondio")})
    assert inc.severity == "baja"
    inc = _report(client, personal_data="si")
    assert inc.severity == "alta"
    # Respuestas de otro tipo se ignoran
    inc = _report(client, g_malware_rescate="si")
    assert inc.guided == {} and inc.severity == "media"
    client.post("/logout")
    login(client, "sofia")
    page = client.get(f"/incidentes/{Incident.query.filter_by(suggested_severity='alta').first().id}").get_data(as_text=True)
    assert "Severidad sugerida" in page and "escribió su contraseña" in page


def test_anonymous_report_hides_identity(client):
    login(client, "laura")
    inc = _report(client, anonymous="1", title="Clave del jefe en un papel")
    assert inc.anonymous and inc.reporter.username == "laura"
    log = AuditLog.query.filter_by(incident_id=inc.id, action="incidente_creado").one()
    assert log.user_id is None and log.ip is None
    assert "Reportaste de forma anónima" in client.get(f"/incidentes/{inc.id}").get_data(as_text=True)
    client.post("/logout")
    login(client, "sofia")
    import re as _re
    detail = client.get(f"/incidentes/{inc.id}").get_data(as_text=True)
    assert "Laura" not in detail.split("<main")[1] and "Reporte anónimo" in detail
    card = next(c for c in _re.split(r"<article", client.get("/gestion").get_data(as_text=True)) if "Clave del jefe" in c)
    assert "Laura" not in card and "Reporte anónimo" in card
    row = next(l for l in client.get("/gestion/exportar.csv").get_data(as_text=True).splitlines() if "Clave del jefe" in l)
    assert "Laura" not in row and "Reporte anónimo" in row


def test_conversation_and_notifications(client):
    from app.models import Notification
    login(client, "carlos")
    inc = _report(client)
    sofia = User.query.filter_by(username="sofia").one()
    assert Notification.query.filter_by(user_id=sofia.id, incident_id=inc.id).count() == 1
    client.post("/logout")
    login(client, "sofia")
    assert "1" in client.get("/notificaciones").get_data(as_text=True)
    client.post(f"/incidentes/{inc.id}/comentarios", data={"body": "¿Hiciste clic en el enlace?"})
    db.session.refresh(inc)
    assert inc.first_response_at is not None  # responder cuenta como primera atención
    assert Notification.query.filter_by(user_id=sofia.id, incident_id=inc.id, read_at=None).count() == 0  # leída al abrir
    client.post("/logout")
    login(client, "carlos")
    page = client.get("/notificaciones").get_data(as_text=True)
    assert f"Seguridad escribió en el incidente #{inc.id}" in page
    page = client.get(f"/incidentes/{inc.id}").get_data(as_text=True)
    assert "¿Hiciste clic en el enlace?" in page
    client.post(f"/incidentes/{inc.id}/comentarios", data={"body": "No, solo lo vi"})
    client.post("/logout")
    login(client, "ana")  # la administración no lee ni escribe en la conversación
    page = client.get(f"/incidentes/{inc.id}").get_data(as_text=True)
    assert "No, solo lo vi" not in page and "2 mensaje(s)" in page
    assert client.post(f"/incidentes/{inc.id}/comentarios", data={"body": "hola admin"}).status_code == 403


def test_playbook_lessons_and_status_notification(client):
    from app.models import Notification
    inc = Incident.query.filter_by(title="Correo falso del banco").one()
    login(client, "sofia")
    client.post(f"/gestion/{inc.id}/playbook", data={"step": ["ph1", "ph2", "zz9"]})
    db.session.refresh(inc)
    assert inc.playbook_done == ["ph1", "ph2"]
    assert AuditLog.query.filter_by(incident_id=inc.id, action="paso_respuesta").count() == 2
    client.post(f"/gestion/{inc.id}", data={"status": "resuelto", "severity": "alta", "notes": "Clave cambiada",
                                           "root_cause": "Correo sin filtro", "lesson": "Activar 2 pasos"})
    db.session.refresh(inc)
    assert inc.lesson == "Activar 2 pasos"
    assert Notification.query.filter_by(user_id=inc.reporter_id, incident_id=inc.id).count() == 1
    client.post("/logout")
    login(client, "carlos")
    assert client.post(f"/gestion/{inc.id}/playbook", data={"step": ["ph3"]}).status_code == 403


def test_campaign_detection_and_indicators(client):
    login(client, "carlos")
    a = _report(client, ioc_sender="Soporte <alerta@banco-seguro.co>", ioc_url="https://www.banco-seguro.co/login")
    client.post("/logout")
    login(client, "laura")
    b = _report(client, ioc_url="http://banco-seguro.co/actualizar")
    c = _report(client, ioc_sender="amiga@gmail.com")  # correo gratuito: no es campaña por dominio
    assert a.ioc_domain == b.ioc_domain == "banco-seguro.co"
    client.post("/logout")
    login(client, "sofia")
    page = client.get(f"/incidentes/{b.id}").get_data(as_text=True)
    assert "Posible campaña: 2 reportes" in page and f"#{a.id}" in page
    assert 'href="http://banco-seguro.co' not in page  # el enlace sospechoso nunca es clicable
    assert "Campaña ×2" in client.get("/gestion").get_data(as_text=True)
    assert "Posible campaña" not in client.get(f"/incidentes/{c.id}").get_data(as_text=True)
    csv = client.get("/gestion/indicadores.csv").get_data(as_text=True)
    assert "dominio,banco-seguro.co,2" in csv


# --- Seguimiento para la gerencia -----------------------------------------

def test_action_items_reminders_and_comparison(client):
    from datetime import timedelta

    from app.models import ActionItem, Notification, ReminderLog
    login(client, "ana")
    sofia = User.query.filter_by(username="sofia").one()
    due = (utcnow().date() + timedelta(days=15)).isoformat()
    client.post("/evaluacion/tareas", data={"question_id": "cifrado", "owner_id": sofia.id, "due_date": due})
    task = ActionItem.query.one()
    assert task.owner_id == sofia.id and task.title.startswith("Activa BitLocker")
    assert Notification.query.filter_by(user_id=sofia.id).filter(Notification.text.like("%plan de acción%")).count() == 1
    page = client.get("/evaluacion").get_data(as_text=True)
    assert "Asignada a Sofía Ríos" in page and "0 de 1 hechas" in page
    # Fecha pasada o empleado como responsable: rechazado
    carlos = User.query.filter_by(username="carlos").one()
    assert client.post("/evaluacion/tareas", data={"question_id": "mfa", "owner_id": carlos.id, "due_date": due}).status_code == 400
    client.post("/evaluacion/tareas", data={"question_id": "mfa", "owner_id": sofia.id, "due_date": "2020-01-01"})
    assert ActionItem.query.count() == 1
    client.post(f"/evaluacion/tareas/{task.id}", data={"action": "done"})
    db.session.refresh(task)
    assert task.done_at is not None
    panel = client.get("/panel").get_data(as_text=True)
    assert "1 de 1 tareas hechas" in panel and "Probar la restauración" in panel and "vs. hace 30 días" in panel
    client.post("/recordatorios/restauracion", data={"next": "//malo.com"})
    assert ReminderLog.query.filter_by(key="restauracion").count() == 1
    assert client.post("/recordatorios/autoevaluacion").status_code == 404  # automático: no se marca a mano
    report = client.get("/reporte").get_data(as_text=True)
    assert "Comparado con el mes anterior" in report
    client.post("/logout")
    login(client, "carlos")
    assert client.post("/evaluacion/tareas", data={"question_id": "mfa"}).status_code == 403


def test_telegram_alert_only_for_high_severity(client, monkeypatch):
    from app import alerts, settings
    sent = []
    monkeypatch.setattr(alerts, "send_telegram", lambda text: sent.append(text) or (True, "ok"))
    login(client, "laura")
    _report(client)  # media: sin alerta
    assert sent == []
    with client.application.test_request_context():
        settings.set_many({"telegram_token": "123:abc", "telegram_chat": "-100"})
    inc = _report(client, g_phishing_clave="si", title="Me robaron la clave del banco")
    assert len(sent) == 1 and f"#{inc.id}" in sent[0]
    assert "robaron" not in sent[0]  # sin título ni descripción por privacidad
    assert not AuditLog.query.filter_by(action="alerta_fallida").count()
    monkeypatch.setattr(alerts, "send_telegram", lambda text: (False, "sin red"))
    _report(client, g_phishing_clave="si")
    assert AuditLog.query.filter_by(action="alerta_fallida").count() == 1


def test_theme_toggle(client):
    login(client, "carlos")
    assert 'data-theme="oscuro"' in client.get("/reportar").get_data(as_text=True)
    r = client.post("/cuenta/tema", data={"next": "/reportar"})
    assert r.headers["Location"].endswith("/reportar")
    assert 'data-theme="claro"' in client.get("/reportar").get_data(as_text=True)
    assert client.post("/cuenta/tema", data={"next": "//malo.com"}).headers["Location"] != "//malo.com"
    assert 'data-theme="oscuro"' in client.get("/reportar").get_data(as_text=True)


def test_pwa_files_and_poster(client):
    m = client.get("/manifest.webmanifest")
    assert m.status_code == 200 and m.json["display"] == "standalone" and len(m.json["icons"]) == 3
    sw = client.get("/sw.js").get_data(as_text=True)
    assert "/sin-conexion" in sw and "navigate" in sw
    assert client.get("/sin-conexion").status_code == 200
    assert client.get("/afiche").status_code == 302  # requiere sesión
    login(client, "carlos")
    assert client.get("/afiche").status_code == 403
    client.post("/logout")
    login(client, "sofia")
    page = client.get("/afiche").get_data(as_text=True)
    assert "data:image/svg+xml" in page and "/reportar" in page and "Afiche con QR" in page
