import re
import secrets

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user

import os
from datetime import date

from flask import current_app, send_file
from flask_login import login_required

from . import alerts, holidays, settings, uploads
from .extensions import db
from .models import ROLES, SEVERITIES, AuditLog, User
from .security import audit, roles_required

bp = Blueprint("admin", __name__)

USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _temp_password():
    # 12 caracteres legibles + 2 dígitos: cumple la política y se puede dictar.
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
    return "".join(secrets.choice(alphabet) for _ in range(10)) + str(secrets.randbelow(90) + 10)


@bp.route("/usuarios", methods=["GET", "POST"])
@roles_required("admin")
def users():
    temp = None
    form = {"username": "", "full_name": "", "email": "", "role": "empleado"}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in form}
        form["username"] = form["username"].lower()
        errors = []
        if not USERNAME_RE.match(form["username"]):
            errors.append("El usuario debe tener 3–64 caracteres: letras minúsculas, números, punto, guion.")
        elif User.query.filter_by(username=form["username"]).first():
            errors.append("Ya existe un usuario con ese nombre.")
        if not 3 <= len(form["full_name"]) <= 120:
            errors.append("Escribe el nombre completo.")
        if form["email"]:
            if not EMAIL_RE.match(form["email"]):
                errors.append("El correo no es válido.")
            elif User.query.filter_by(email=form["email"].lower()).first():
                errors.append("Ya existe un usuario con ese correo.")
        if form["role"] not in ROLES:
            errors.append("Rol inválido.")
        if errors:
            for e in errors:
                flash(e, "err")
        else:
            temp = _temp_password()
            user = User(
                username=form["username"],
                full_name=form["full_name"],
                email=form["email"].lower() or None,
                role=form["role"],
                must_change_password=True,
            )
            user.set_password(temp)
            db.session.add(user)
            db.session.flush()
            audit("usuario_creado", f"{user.username} ({ROLES[user.role]})")
            db.session.commit()
            temp = (user, temp)
            form = {"username": "", "full_name": "", "email": "", "role": "empleado"}

    all_users = User.query.order_by(User.is_active_flag.desc(), User.full_name).all()
    return render_template("admin/users.html", users=all_users, form=form, temp=temp)


@bp.route("/usuarios/<int:user_id>", methods=["GET", "POST"])
@roles_required("admin")
def edit_user(user_id):
    user = db.get_or_404(User, user_id)
    temp = None
    if request.method == "POST":
        action = request.form.get("action")
        is_self = user.id == current_user.id

        if action == "save":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower() or None
            role = request.form.get("role", user.role)
            active = request.form.get("active") == "1"
            errors = []
            if not 3 <= len(full_name) <= 120:
                errors.append("Escribe el nombre completo.")
            if email and not EMAIL_RE.match(email):
                errors.append("El correo no es válido.")
            elif email and User.query.filter(User.email == email, User.id != user.id).first():
                errors.append("Ya existe un usuario con ese correo.")
            if role not in ROLES:
                abort(400)
            if is_self and (role != "admin" or not active):
                errors.append("No puedes quitarte el rol de administrador ni desactivar tu propia cuenta.")
            if errors:
                for e in errors:
                    flash(e, "err")
            else:
                changes = []
                if role != user.role:
                    changes.append(f"rol {ROLES[user.role]} → {ROLES[role]}")
                if active != user.is_active_flag:
                    changes.append("activado" if active else "desactivado")
                if full_name != user.full_name or email != user.email:
                    changes.append("datos personales")
                user.full_name, user.email, user.role, user.is_active_flag = full_name, email, role, active
                if changes:
                    audit("usuario_modificado", f"{user.username}: " + "; ".join(changes))
                db.session.commit()
                flash("Usuario actualizado.", "ok")
                return redirect(url_for("admin.users"))

        elif action == "reset":
            if is_self:
                flash("Para tu propia cuenta usa «Cambiar contraseña».", "err")
            else:
                temp = _temp_password()
                user.set_password(temp)
                user.must_change_password = True
                user.failed_logins = 0
                user.locked_until = None
                audit("contrasena_restablecida", user.username)
                db.session.commit()

        elif action == "reset_2fa":
            if is_self:
                flash("Para tu propia cuenta usa «Seguridad de la cuenta».", "err")
            else:
                user.totp_secret, user.totp_enabled, user.totp_last_step = None, False, None
                audit("2fa_restablecido", f"{user.username}: se quitó la verificación en dos pasos")
                db.session.commit()
                flash("Se quitó la verificación en dos pasos. El usuario podrá activarla de nuevo.", "ok")

        elif action == "unlock":
            user.failed_logins = 0
            user.locked_until = None
            audit("usuario_desbloqueado", user.username)
            db.session.commit()
            flash("Cuenta desbloqueada.", "ok")
        else:
            abort(400)

    return render_template("admin/edit_user.html", user=user, temp=temp)


@bp.route("/auditoria")
@roles_required("admin")
def audit_log():
    action = request.args.get("action", "")
    q = AuditLog.query
    if action:
        q = q.filter(AuditLog.action == action)
    page = q.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).paginate(per_page=25, error_out=False)
    actions = [a for (a,) in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action)]
    return render_template("admin/audit.html", page=page, action=action, actions=actions)


@bp.route("/empresa", methods=["GET", "POST"])
@roles_required("admin")
def company():
    if request.method == "POST" and request.form.get("action") == "telegram_test":
        ok, msg = alerts.send_telegram("✅ Prueba de CiberGuard: las alertas por Telegram funcionan.")
        flash(msg, "ok" if ok else "err")
        return redirect(url_for("admin.company"))
    if request.method == "POST":
        values, errors = {}, []
        values["company_name"] = request.form.get("company_name", "").strip()[:80]
        for sev in SEVERITIES:
            raw = request.form.get(f"sla_{sev}", "")
            if not raw.isdigit() or not 1 <= int(raw) <= 720:
                errors.append(f"El plazo para severidad {SEVERITIES[sev].lower()} debe ser un número de horas entre 1 y 720.")
            else:
                values[f"sla_{sev}"] = raw
        if not (values.get("sla_alta", "0").isdigit() and values.get("sla_media", "0").isdigit()
                and int(values.get("sla_alta", 0)) <= int(values.get("sla_media", 0)) <= int(values.get("sla_baja", 10**6))):
            errors.append("Los plazos deben ir de menor a mayor: alta ≤ media ≤ baja.")
        share = request.form.get("incident_share", "")
        if not share.isdigit() or not 0 <= int(share) <= 100:
            errors.append("El peso del riesgo por incidentes debe estar entre 0 y 100.")
        else:
            values["incident_share"] = share
        extra, bad = [], []
        for line in request.form.get("extra_holidays", "").split():
            try:
                extra.append(date.fromisoformat(line.strip()).isoformat())
            except ValueError:
                bad.append(line)
        if bad:
            errors.append("Fechas no válidas en festivos adicionales: " + ", ".join(bad[:3]) + ". Usa el formato AAAA-MM-DD.")
        values["extra_holidays"] = "\n".join(sorted(set(extra)))
        values["telegram_chat"] = request.form.get("telegram_chat", "").strip()[:40]
        token = request.form.get("telegram_token", "").strip()
        if token and token != "********":
            values["telegram_token"] = token[:120]
        elif request.form.get("telegram_clear"):
            values["telegram_token"] = ""
        logo = request.files.get("logo")
        if logo and logo.filename:
            data = logo.read(512 * 1024 + 1)
            kind = uploads.detect(data[:8])
            if len(data) > 512 * 1024 or kind not in ("png", "jpg"):
                errors.append("El logo debe ser PNG o JPG de máximo 512 KB.")
            else:
                name = "logo." + kind
                with open(os.path.join(uploads.upload_dir(), name), "wb") as out:
                    out.write(data)
                values["logo"] = name
        if request.form.get("logo_clear"):
            values["logo"] = ""
        if errors:
            for e in errors:
                flash(e, "err")
        else:
            settings.set_many(values)
            audit("empresa_configurada", "Configuración de la empresa actualizada")
            db.session.commit()
            flash("Configuración guardada.", "ok")
            return redirect(url_for("admin.company"))
    year = date.today().year
    return render_template(
        "admin/company.html", s=settings.all_settings(), sla=settings.sla_hours(),
        holidays=[h for y in (year, year + 1) for h in holidays.colombia(y)],
        telegram_ready=alerts.telegram_configured(),
    )


@bp.route("/logo")
@login_required
def logo():
    name = settings.get("logo")
    path = os.path.join(uploads.upload_dir(), name) if name else ""
    if not name or not os.path.exists(path):
        abort(404)
    return send_file(path, max_age=300)
