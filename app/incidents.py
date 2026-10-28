import csv
import io
import os

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from . import compliance, content, risk, uploads
from .extensions import db
from .models import (
    CLOSED_STATES, PERSONAL_DATA, SEVERITIES, SLA_HOURS, STATES, TYPES, Attachment, Incident, User, utcnow,
)
from .security import audit, roles_required

bp = Blueprint("incidents", __name__)

STAFF = ("seguridad", "admin")


@bp.route("/reportar", methods=["GET", "POST"])
@login_required
def report():
    form = {"type": "phishing", "title": "", "description": "", "personal_data": "no_se"}
    if request.method == "POST":
        form = {k: request.form.get(k, v if k == "personal_data" else "").strip() for k, v in form.items()}
        errors = []
        if form["type"] not in TYPES:
            errors.append("Selecciona un tipo de incidente válido.")
        if not 5 <= len(form["title"]) <= 150:
            errors.append("El resumen debe tener entre 5 y 150 caracteres.")
        if not 10 <= len(form["description"]) <= 5000:
            errors.append("Describe lo ocurrido (entre 10 y 5000 caracteres).")
        if form["personal_data"] not in PERSONAL_DATA:
            errors.append("Indica si se pudieron exponer datos personales.")
        if errors:
            for e in errors:
                flash(e, "err")
        else:
            inc = Incident(reporter=current_user, **form)
            db.session.add(inc)
            db.session.flush()
            audit("incidente_creado", f"#{inc.id} {inc.title}", incident=inc)
            saved, file_errors = uploads.save_files(request.files.getlist("evidence"), inc, current_user)
            if saved:
                audit("evidencia_adjunta", f"#{inc.id}: {saved} archivo(s)", incident=inc)
            db.session.commit()
            for e in file_errors:
                flash(e, "err")
            flash("Incidente reportado. El encargado de seguridad lo revisará. Mientras tanto, sigue estos pasos.", "ok")
            return redirect(url_for("incidents.detail", incident_id=inc.id, nuevo=1))

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
        "incidents/detail.html", inc=inc, can_edit=can_edit, events=events,
        analysts=_analysts() if can_edit else [], guide=content.GUIDES.get(inc.type),
        is_new=request.args.get("nuevo") == "1", sic=compliance.sic_status(inc) if inc.personal_data == "si" else None,
        can_upload=_can_upload(inc), max_files=uploads.MAX_PER_INCIDENT,
    )


def _can_see(inc):
    return current_user.role in STAFF or inc.reporter_id == current_user.id


def _can_upload(inc):
    return (current_user.role == "seguridad" or inc.reporter_id == current_user.id) and len(
        inc.attachments) < uploads.MAX_PER_INCIDENT


@bp.route("/incidentes/<int:incident_id>/evidencia", methods=["POST"])
@login_required
def add_evidence(incident_id):
    inc = db.get_or_404(Incident, incident_id)
    if not _can_see(inc):
        abort(404)
    if not _can_upload(inc):
        abort(403)
    saved, errors = uploads.save_files(request.files.getlist("evidence"), inc, current_user)
    if saved:
        audit("evidencia_adjunta", f"#{inc.id}: {saved} archivo(s)", incident=inc)
        db.session.commit()
        flash(f"{saved} archivo(s) adjuntado(s).", "ok")
    for e in errors or ([] if saved else ["Selecciona al menos un archivo."]):
        flash(e, "err")
    return redirect(url_for("incidents.detail", incident_id=inc.id))


@bp.route("/adjuntos/<int:attachment_id>")
@login_required
def attachment(attachment_id):
    att = db.get_or_404(Attachment, attachment_id)
    if not _can_see(att.incident):
        abort(404)
    path = os.path.join(uploads.upload_dir(), att.stored_name)
    if not os.path.exists(path):
        abort(404)
    resp = send_file(path, mimetype=att.mime, as_attachment=not att.is_image, download_name=att.original_name,
                     max_age=0)
    resp.headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'"
    return resp


def _filtered_query():
    q = Incident.query
    f = {k: request.args.get(k, "") for k in ("status", "severity", "type", "q", "sla", "datos")}
    if f["status"] in STATES:
        q = q.filter(Incident.status == f["status"])
    if f["severity"] in SEVERITIES:
        q = q.filter(Incident.severity == f["severity"])
    if f["type"] in TYPES:
        q = q.filter(Incident.type == f["type"])
    if f["q"]:
        like = f"%{f['q'][:100]}%"
        q = q.filter(db.or_(Incident.title.ilike(like), Incident.description.ilike(like)))
    if f["datos"] == "si":
        q = q.filter(Incident.personal_data == "si")
    q = q.order_by(Incident.created_at.desc())
    if f["sla"] == "vencido":
        # El plazo depende de la severidad: se filtra en Python (volúmenes de pyme).
        ids = [i.id for i in q.all() if i.sla_state() == "vencido"]
        q = Incident.query.filter(Incident.id.in_(ids or [0])).order_by(Incident.created_at.desc())
    return q, f


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
    personal = request.form.get("personal_data", inc.personal_data)
    sic_raw = request.form.get("sic_reported_at", "")
    sic_date = compliance.as_date(sic_raw) if sic_raw else None
    if status not in STATES or severity not in SEVERITIES or personal not in PERSONAL_DATA:
        abort(400)
    if sic_raw and (not sic_date or sic_date > utcnow().date()):
        flash("La fecha de reporte a la SIC no es válida.", "err")
        return redirect(url_for("incidents.detail", incident_id=inc.id))
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
    if personal != inc.personal_data:
        changes.append(f"datos personales: {PERSONAL_DATA[inc.personal_data]} → {PERSONAL_DATA[personal]}")
    if "sic_reported_at" in request.form and sic_date != inc.sic_reported_at:
        changes.append(f"reportado a la SIC el {sic_date.strftime('%d/%m/%Y')}" if sic_date else "se quitó la fecha de reporte a la SIC")

    if changes:
        inc.status, inc.severity, inc.notes, inc.assigned_to_id = status, severity, notes, assigned_id
        inc.personal_data = personal
        if "sic_reported_at" in request.form:
            inc.sic_reported_at = sic_date
        if inc.first_response_at is None and (status != "reportado" or assigned_id or notes):
            inc.first_response_at = utcnow()
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
    w.writerow(["ID", "Fecha (UTC)", "Tipo", "Título", "Reportó", "Severidad", "Estado", "Asignado",
                "Primera atención", "Tiempo de atención", "Cerrado", "Datos personales", "Reportado a SIC", "Notas"])
    sla_labels = {"cumplido": "En plazo", "incumplido": "Fuera de plazo", "vencido": "Vencido", "en_plazo": "Pendiente"}
    fmt = lambda d: d.isoformat(timespec="minutes") if d else ""  # noqa: E731
    for i in q.all():
        w.writerow([
            i.id, fmt(i.created_at), TYPES[i.type], _safe(i.title), i.reporter.full_name,
            SEVERITIES[i.severity], STATES[i.status], i.assigned_to.full_name if i.assigned_to else "",
            fmt(i.first_response_at), sla_labels[i.sla_state()], fmt(i.resolved_at), PERSONAL_DATA[i.personal_data],
            i.sic_reported_at.isoformat() if i.sic_reported_at else "", _safe(i.notes),
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
    return render_template("incidents/dashboard.html", r=risk.compute(), sla_hours=SLA_HOURS)


MONTHS = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre",
          "noviembre", "diciembre"]


@bp.route("/reporte")
@roles_required(*STAFF)
def monthly_report():
    now = utcnow()
    try:
        year, month = (int(x) for x in request.args.get("mes", "").split("-"))
        if not (2000 <= year <= now.year and 1 <= month <= 12):
            raise ValueError
    except ValueError:
        year, month = now.year, now.month
    options = []
    y, m = now.year, now.month
    for _ in range(12):
        options.append((f"{y}-{m:02d}", f"{MONTHS[m - 1].capitalize()} {y}"))
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)
    return render_template(
        "incidents/monthly.html", s=risk.month_summary(year, month), label=f"{MONTHS[month - 1]} de {year}",
        selected=f"{year}-{month:02d}", options=options, level=risk.level, generated=now,
    )
