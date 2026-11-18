import time
from datetime import timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from . import totp
from .extensions import db
from .models import User, utcnow
from .security import audit, password_problems, safe_next

bp = Blueprint("auth", __name__)

# Hash ficticio para que un usuario inexistente tarde lo mismo que una clave errada.
_DUMMY_HASH = generate_password_hash("contrasena-ficticia-para-tiempo-constante")
PENDING_2FA_SECONDS = 300


@bp.route("/login", methods=["GET", "POST"])
def login():
    from . import home_for

    if current_user.is_authenticated:
        return redirect(home_for(current_user))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        # Mismo mensaje para usuario inexistente y clave errada: no revela qué cuentas existen.
        generic = "Usuario o contraseña incorrectos."

        if user and user.is_locked():
            audit("login_bloqueado", f"Intento sobre cuenta bloqueada '{username}'", user=user)
            db.session.commit()
            flash("La cuenta está bloqueada temporalmente por intentos fallidos. Intenta más tarde.", "err")
            return render_template("auth/login.html", username=username), 429

        if not user:
            check_password_hash(_DUMMY_HASH, password)
        if not user or not user.check_password(password) or not user.is_active:
            _register_failure(user, f"Usuario '{username[:64]}'")
            flash(generic, "err")
            return render_template("auth/login.html", username=username), 401

        if user.totp_enabled:
            # Segundo paso: la sesión solo recuerda quién validó la contraseña y cuándo.
            session.clear()
            session["2fa_uid"] = user.id
            session["2fa_at"] = time.time()
            return redirect(url_for("auth.verify_2fa"))
        return _complete_login(user)

    return render_template("auth/login.html")


def _register_failure(user, detail):
    if user:
        user.failed_logins += 1
        if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
            user.locked_until = utcnow() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
            user.failed_logins = 0
            audit("cuenta_bloqueada", "Demasiados intentos fallidos", user=user)
    audit("login_fallido", detail, user=user)
    db.session.commit()


def _complete_login(user, method="contraseña"):
    from . import home_for

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    session.clear()  # evita fijación de sesión
    login_user(user)
    session.permanent = True
    audit("login", f"Inicio de sesión ({method})", user=user)
    db.session.commit()
    return redirect(home_for(user))


@bp.route("/login/verificar", methods=["GET", "POST"])
def verify_2fa():
    uid, started = session.get("2fa_uid"), session.get("2fa_at", 0)
    user = db.session.get(User, uid) if uid else None
    if not user or not user.is_active or not user.totp_enabled or time.time() - started > PENDING_2FA_SECONDS:
        session.clear()
        flash("Vuelve a iniciar sesión.", "err")
        return redirect(url_for("auth.login"))
    if user.is_locked():
        session.clear()
        flash("La cuenta está bloqueada temporalmente por intentos fallidos. Intenta más tarde.", "err")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        step = totp.verify(user.totp_secret, request.form.get("code", ""), user.totp_last_step)
        if step is None:
            _register_failure(user, "Código de verificación incorrecto")
            flash("El código no es válido o ya fue usado. Revisa la hora de tu celular y usa el código actual.", "err")
            return render_template("auth/verify_2fa.html"), 401
        user.totp_last_step = step
        return _complete_login(user, "contraseña + código")
    return render_template("auth/verify_2fa.html")


@bp.route("/cuenta/seguridad", methods=["GET", "POST"])
@login_required
def security_settings():
    pending = session.get("2fa_setup")
    if request.method == "POST":
        action = request.form.get("action")
        if action == "start" and not current_user.totp_enabled:
            session["2fa_setup"] = pending = totp.new_secret()
        elif action == "confirm" and pending and not current_user.totp_enabled:
            step = totp.verify(pending, request.form.get("code", ""))
            if step is None:
                flash("El código no coincide. Escanea de nuevo el código QR y escribe el número actual.", "err")
            else:
                current_user.totp_secret, current_user.totp_enabled, current_user.totp_last_step = pending, True, step
                session.pop("2fa_setup", None)
                audit("2fa_activado", "Activó la verificación en dos pasos")
                db.session.commit()
                flash("Verificación en dos pasos activada. Desde ahora te pediremos un código al ingresar.", "ok")
                return redirect(url_for("auth.security_settings"))
        elif action == "disable" and current_user.totp_enabled:
            if not current_user.check_password(request.form.get("password", "")):
                flash("La contraseña no es correcta.", "err")
            else:
                current_user.totp_secret, current_user.totp_enabled, current_user.totp_last_step = None, False, None
                audit("2fa_desactivado", "Desactivó la verificación en dos pasos")
                db.session.commit()
                flash("Verificación en dos pasos desactivada.", "ok")
                return redirect(url_for("auth.security_settings"))
        elif action == "cancel":
            session.pop("2fa_setup", None)
            pending = None

    qr = None
    if pending and not current_user.totp_enabled:
        qr = totp.qr_data_uri(totp.provisioning_uri(pending, current_user.username))
    return render_template(
        "auth/security.html", pending=pending, qr=qr, secret_txt=totp.format_secret(pending) if pending else ""
    )


@bp.route("/cuenta/tema", methods=["POST"])
@login_required
def toggle_theme():
    current_user.theme = "claro" if current_user.theme != "claro" else "oscuro"
    db.session.commit()
    return redirect(safe_next(request.form.get("next", ""), url_for("index")))


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", "Cierre de sesión")
    db.session.commit()
    logout_user()
    session.clear()
    flash("Sesión cerrada.", "ok")
    return redirect(url_for("auth.login"))


@bp.route("/cuenta/contrasena", methods=["GET", "POST"])
@login_required
def change_password():
    from . import home_for

    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        errors = []
        if not current_user.check_password(current):
            errors.append("La contraseña actual no es correcta.")
        if new != confirm:
            errors.append("La nueva contraseña y su confirmación no coinciden.")
        if new == current:
            errors.append("La nueva contraseña debe ser distinta a la actual.")
        errors += password_problems(new, current_user.username)
        if errors:
            for e in errors:
                flash(e, "err")
            return render_template("auth/change_password.html"), 400
        current_user.set_password(new)
        current_user.must_change_password = False
        audit("cambio_contrasena", "El usuario cambió su contraseña")
        db.session.commit()
        flash("Contraseña actualizada.", "ok")
        return redirect(home_for(current_user))
    return render_template("auth/change_password.html")
