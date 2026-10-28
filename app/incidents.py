import csv
import io

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from . import risk
from .extensions import db
from .models import CLOSED_STATES, SEVERITIES, STATES, TYPES, Incident, User, utcnow
from .security import audit, roles_required

bp = Blueprint("incidents", __name__)

STAFF = ("seguridad", "admin")


@bp.route("/reportar", methods=["GET", "POST"])
@login_required
def report():
    form = {"type": "phishing", "title": "", "description": ""}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in form}
        errors = []
        if form["type"] not in TYPES:
            errors.append("Selecciona un tipo de incidente válido.")
        if not 5 <= len(form["title"]) <= 150:
            errors.append("El resumen debe tener entre 5 y 150 caracteres.")
        if not 10 <= len(form["description"]) <= 5000:
            errors.append("Describe lo ocurrido (entre 10 y 5000 caracteres).")
        if errors:
            for e in errors:
                flash(e, "err")
        else:
            inc = Incident(reporter=current_user, **form)
            db.session.add(inc)
            db.session.flush()
            audit("incidente_creado", f"#{inc.id} {inc.title}", incident=inc)
            db.session.commit()
            flash("Incidente reportado correctamente. El encargado de seguridad lo revisará.", "ok")
            return redirect(url_for("incidents.report"))

    mine = Incident.query.filter_by(reporter_id=current_user.id).order_by(Incident.created_at.desc()).all()
    return render_template("incidents/report.html", form=form, mine=mine), (400 if request.method == "POST" else 200)


@bp.route("/incidentes/<int:incident_id>")
@login_required
def detail(incident_id):
    inc = db.get_or_404(Incident, incident_id)
    if current_user.role not in STAFF and inc.reporter_id != current_user.id:
        abort(404)  # no revela la existencia de incidentes ajenos
    can_edit = current_user.role == "seguridad"
    events = inc.events.all() if current_user.role in STAFF else []
    return render_template(
        "incidents/detail.html", inc=inc, can_edit=can_edit, events=events, analysts=_analysts() if can_edit else []
    )


def _filtered_query():
    q = Incident.query
    f = {k: request.args.get(k, "") for k in ("status", "severity", "type", "q")}
    if f["status"] in STATES:
        q = q.filter(Incident.status == f["status"])
    if f["severity"] in SEVERITIES:
        q = q.filter(Incident.severity == f["severity"])
    if f["type"] in TYPES:
        q = q.filter(Incident.type == f["type"])
    if f["q"]:
        like = f"%{f['q'][:100]}%"
        q = q.filter(db.or_(Incident.title.ilike(like), Incident.description.ilike(like)))
    return q.order_by(Incident.created_at.desc()), f


def _analysts():
    return User.query.filter_by(role="seguridad", is_active_flag=True).order_by(User.full_name).all()


@bp.route("/gestion")
@roles_required(*STAFF)
def manage():
    q, f = _filtered_query()
    page = q.paginate(per_page=20, error_out=False)
    return render_template(
        "incidents/manage.html", page=page, f=f, can_edit=current_user.role == "seguridad", analysts=_analysts()
    )


@bp.route("/gestion/<int:incident_id>", methods=["POST"])
@roles_required("seguridad")
def update(incident_id):
    inc = db.get_or_404(Incident, incident_id)
    status = request.form.get("status", inc.status)
    severity = request.form.get("severity", inc.severity)
    notes = request.form.get("notes", inc.notes).strip()[:5000]
    assigned = request.form.get("assigned_to_id", "")
    if status not in STATES or severity not in SEVERITIES:
        abort(400)
    assigned_id = int(assigned) if assigned.isdigit() else None
    if assigned_id and not any(a.id == assigned_id for a in _analysts()):
        abort(400)

    changes = []
    if status != inc.status:
        changes.append(f"estado: {STATES[inc.status]} → {STATES[status]}")
    if severity != inc.severity:
        changes.append(f"severidad: {SEVERITIES[inc.severity]} → {SEVERITIES[severity]}")
    if notes != inc.notes:
        changes.append("notas actualizadas")
    if assigned_id != inc.assigned_to_id:
        name = db.session.get(User, assigned_id).full_name if assigned_id else "nadie"
        changes.append(f"asignado a {name}")

    if changes:
        inc.status, inc.severity, inc.notes, inc.assigned_to_id = status, severity, notes, assigned_id
        if status in CLOSED_STATES:
            inc.resolved_at = inc.resolved_at or utcnow()
        else:
            inc.resolved_at = None
        audit("incidente_actualizado", f"#{inc.id}: " + "; ".join(changes), incident=inc)
        db.session.commit()
        flash(f"Incidente #{inc.id} actualizado.", "ok")
    else:
        flash("No había cambios que guardar.", "ok")
    nxt = request.form.get("next", "")
    # Solo rutas internas: evita redirecciones abiertas.
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        nxt = url_for("incidents.manage")
    return redirect(nxt)


@bp.route("/gestion/exportar.csv")
@roles_required(*STAFF)
def export_csv():
    q, _ = _filtered_query()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ID", "Fecha", "Tipo", "Título", "Reportó", "Severidad", "Estado", "Asignado", "Cerrado", "Notas"])
    for i in q.all():
        w.writerow([
            i.id, i.created_at.isoformat(timespec="minutes"), TYPES[i.type], _safe(i.title), i.reporter.full_name,
            SEVERITIES[i.severity], STATES[i.status], i.assigned_to.full_name if i.assigned_to else "",
            i.resolved_at.isoformat(timespec="minutes") if i.resolved_at else "", _safe(i.notes),
        ])
    audit("exportacion_csv", "Exportó incidentes a CSV")
    db.session.commit()
    # BOM para que Excel abra bien las tildes.
    return Response(
        "﻿" + buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=incidentes.csv"},
    )


def _safe(text):
    # Evita inyección de fórmulas al abrir el CSV en Excel.
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


@bp.route("/panel")
@roles_required(*STAFF)
def dashboard():
    return render_template("incidents/dashboard.html", r=risk.compute())
