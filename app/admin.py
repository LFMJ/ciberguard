import re
import secrets

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user

from .extensions import db
from .models import ROLES, AuditLog, User
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
    page = q.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).paginate(per_page=50, error_out=False)
    actions = [a for (a,) in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action)]
    return render_template("admin/audit.html", page=page, action=action, actions=actions)
