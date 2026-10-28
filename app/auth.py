from datetime import timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db
from .models import User, utcnow
from .security import audit, password_problems

bp = Blueprint("auth", __name__)

# Hash ficticio para que un usuario inexistente tarde lo mismo que una clave errada.
_DUMMY_HASH = generate_password_hash("contrasena-ficticia-para-tiempo-constante")


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
            if user:
                user.failed_logins += 1
                if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
                    user.locked_until = utcnow() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
                    user.failed_logins = 0
                    audit("cuenta_bloqueada", "Demasiados intentos fallidos", user=user)
            audit("login_fallido", f"Usuario '{username[:64]}'", user=user)
            db.session.commit()
            flash(generic, "err")
            return render_template("auth/login.html", username=username), 401

        user.failed_logins = 0
        user.locked_until = None
        user.last_login_at = utcnow()
        session.clear()  # evita fijación de sesión
        login_user(user)
        session.permanent = True
        audit("login", "Inicio de sesión", user=user)
        db.session.commit()
        return redirect(home_for(user))

    return render_template("auth/login.html")


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
