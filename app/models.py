import json
from datetime import datetime, timedelta, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

ROLES = {
    "empleado": "Empleado",
    "seguridad": "Encargado de seguridad",
    "admin": "Administrador",
}
TYPES = {
    "phishing": "Phishing / correo sospechoso",
    "malware": "Malware / archivo sospechoso",
    "contrasena": "Contraseñas",
    "acceso_indebido": "Acceso indebido",
    "otro": "Otro",
}
STATES = {
    "reportado": "Reportado",
    "en_revision": "En revisión",
    "resuelto": "Resuelto",
    "descartado": "Descartado",
}
SEVERITIES = {"baja": "Baja", "media": "Media", "alta": "Alta"}
# Tiempo máximo para la primera atención según severidad (horas).
SLA_HOURS = {"alta": 4, "media": 24, "baja": 72}
PERSONAL_DATA = {"no": "No", "no_se": "No sé", "si": "Sí"}
ALLOWED_UPLOADS = {"png": "image/png", "jpg": "image/jpeg", "pdf": "application/pdf"}
OPEN_STATES = ("reportado", "en_revision")
CLOSED_STATES = ("resuelto", "descartado")


def utcnow():
    # Se guarda en UTC sin zona (SQLite y MySQL no conservan tzinfo).
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    role = db.Column(db.String(20), nullable=False, default="empleado")
    password_hash = db.Column(db.String(255), nullable=False)
    is_active_flag = db.Column("is_active", db.Boolean, nullable=False, default=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=True)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    totp_last_step = db.Column(db.Integer, nullable=True)  # evita reutilizar un código

    incidents = db.relationship("Incident", back_populates="reporter", foreign_keys="Incident.reporter_id")

    @property
    def is_active(self):
        return self.is_active_flag

    @property
    def role_name(self):
        return ROLES.get(self.role, self.role)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    def is_locked(self):
        return self.locked_until is not None and self.locked_until > utcnow()


class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    type = db.Column(db.String(30), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(10), nullable=False, default="media")
    status = db.Column(db.String(20), nullable=False, default="reportado", index=True)
    notes = db.Column(db.Text, nullable=False, default="")
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    first_response_at = db.Column(db.DateTime, nullable=True)
    personal_data = db.Column(db.String(10), nullable=False, default="no_se")
    sic_reported_at = db.Column(db.Date, nullable=True)

    reporter = db.relationship("User", back_populates="incidents", foreign_keys=[reporter_id])
    assigned_to = db.relationship("User", foreign_keys=[assigned_to_id])
    events = db.relationship(
        "AuditLog", back_populates="incident", order_by="AuditLog.created_at", lazy="dynamic"
    )

    attachments = db.relationship("Attachment", back_populates="incident", order_by="Attachment.created_at")

    @property
    def is_open(self):
        return self.status in OPEN_STATES

    @property
    def sla_due(self):
        return self.created_at + timedelta(hours=SLA_HOURS.get(self.severity, 24))

    def sla_state(self, now=None):
        """'cumplido', 'incumplido' (atendido tarde), 'vencido' (sin atender y fuera de plazo) o 'en_plazo'."""
        now = now or utcnow()
        if self.first_response_at:
            return "cumplido" if self.first_response_at <= self.sla_due else "incumplido"
        if self.status not in OPEN_STATES:
            return "cumplido"
        return "vencido" if now > self.sla_due else "en_plazo"

    @property
    def needs_sic_report(self):
        return self.personal_data == "si" and self.sic_reported_at is None and self.status != "descartado"


class AuditLog(db.Model):
    """Bitácora inmutable: inicios de sesión, cambios de usuarios y de incidentes."""

    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=True, index=True)
    action = db.Column(db.String(40), nullable=False)
    detail = db.Column(db.Text, nullable=False, default="")
    ip = db.Column(db.String(45), nullable=True)

    user = db.relationship("User")
    incident = db.relationship("Incident", back_populates="events")


class Attachment(db.Model):
    """Evidencia adjunta (capturas o PDF). El archivo vive en instance/uploads con nombre aleatorio."""

    __tablename__ = "attachments"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False, index=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    original_name = db.Column(db.String(200), nullable=False)
    stored_name = db.Column(db.String(64), nullable=False, unique=True)
    mime = db.Column(db.String(40), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    incident = db.relationship("Incident", back_populates="attachments")
    uploader = db.relationship("User")

    @property
    def is_image(self):
        return self.mime.startswith("image/")


class Assessment(db.Model):
    """Autoevaluación de madurez (basada en CIS Controls IG1)."""

    __tablename__ = "assessments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    answers_json = db.Column(db.Text, nullable=False, default="{}")
    score = db.Column(db.Integer, nullable=False, default=0)  # 0–100, más alto = más maduro

    user = db.relationship("User")

    @property
    def answers(self):
        return json.loads(self.answers_json or "{}")


class QuizAttempt(db.Model):
    """Resultado de una microcapacitación."""

    __tablename__ = "quiz_attempts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    correct = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)

    user = db.relationship("User")

    @property
    def pct(self):
        return round(self.correct / self.total * 100) if self.total else 0
