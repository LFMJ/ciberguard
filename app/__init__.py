import os
from datetime import timezone
from zoneinfo import ZoneInfo

import click
from flask import Flask, redirect, render_template, request, url_for
from flask_login import current_user

from config import Config
from .extensions import csrf, db, login_manager
from .models import PERSONAL_DATA, ROLES, SEVERITIES, SLA_HOURS, STATES, TYPES, User, utcnow


def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from .admin import bp as admin_bp
    from .assessment import bp as assessment_bp
    from .auth import bp as auth_bp
    from .incidents import bp as incidents_bp
    from .training import bp as training_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(assessment_bp)
    app.register_blueprint(training_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")

    _register_template_helpers(app)
    _register_hooks(app)
    _register_errors(app)
    _register_cli(app)

    with app.app_context():
        from . import schema

        schema.upgrade()
        db.create_all()
    return app


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    return user if user and user.is_active else None


def home_for(user):
    if user.role == "seguridad":
        return url_for("incidents.manage")
    if user.role == "admin":
        return url_for("incidents.dashboard")
    return url_for("incidents.report")


def _register_template_helpers(app):
    tz = ZoneInfo(app.config["TIMEZONE"])

    @app.template_filter("fecha")
    def fecha(value):
        if not value:
            return "—"
        local = value.replace(tzinfo=timezone.utc).astimezone(tz)
        return local.strftime("%d/%m/%Y %I:%M %p").replace("AM", "a. m.").replace("PM", "p. m.")

    @app.context_processor
    def labels():
        return {"TYPES": TYPES, "STATES": STATES, "SEVERITIES": SEVERITIES, "ROLES": ROLES,
                "PERSONAL_DATA": PERSONAL_DATA, "SLA_HOURS": SLA_HOURS}

    app.jinja_env.globals["now_utc"] = utcnow

    @app.template_filter("fecha_corta")
    def fecha_corta(value):
        return value.strftime("%d/%m/%Y") if value else "—"

    @app.template_filter("horas")
    def horas(td):
        """Duración legible: «3 h», «2 días»."""
        h = abs(td.total_seconds()) / 3600
        return f"{round(h)} h" if h < 48 else f"{round(h / 24)} días"


def _register_hooks(app):
    @app.before_request
    def force_password_change():
        # Usuarios con contraseña temporal solo pueden cambiarla o salir.
        if (
            current_user.is_authenticated
            and current_user.must_change_password
            and request.endpoint not in ("auth.change_password", "auth.logout", "static")
        ):
            return redirect(url_for("auth.change_password"))

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
        )
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if current_user.is_authenticated:
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(home_for(current_user))
        return redirect(url_for("auth.login"))


def _register_errors(app):
    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403, msg="No tienes permiso para ver esta página."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, msg="La página que buscas no existe."), 404

    @app.errorhandler(413)
    def too_large(_e):
        return render_template("error.html", code=413, msg="Los archivos son demasiado grandes. Máximo 2 MB por archivo."), 413

    @app.errorhandler(400)
    def bad_request(_e):
        return render_template(
            "error.html", code=400, msg="La solicitud no es válida o el formulario expiró. Vuelve a intentarlo."
        ), 400


def _register_cli(app):
    @app.cli.command("create-admin")
    @click.option("--username", prompt="Usuario")
    @click.option("--name", prompt="Nombre completo")
    @click.password_option(prompt="Contraseña")
    def create_admin(username, name, password):
        """Crea el primer administrador."""
        from .security import password_problems

        problems = password_problems(password, username)
        if problems:
            raise click.ClickException(" ".join(problems))
        if User.query.filter_by(username=username.lower()).first():
            raise click.ClickException("Ese usuario ya existe.")
        user = User(username=username.lower(), full_name=name, role="admin", must_change_password=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Administrador '{user.username}' creado.")

    @app.cli.command("seed-demo")
    def seed_demo():
        """Carga los usuarios e incidentes de la demo (solo para presentaciones)."""
        from .seed import seed

        for line in seed():
            click.echo(line)
