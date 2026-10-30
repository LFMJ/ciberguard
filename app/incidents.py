import csv
import io
import json
import os
from datetime import timedelta

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from . import alerts, compliance, content, followup, indicators, notify, risk, settings, uploads
from .extensions import db
from .models import (
    CLOSED_STATES, PERSONAL_DATA, SEVERITIES, STATES, TYPES, ActionItem, Attachment, Comment, Incident, Notification,
    User,
    utcnow,
)
from .security import audit, roles_required, safe_next

bp = Blueprint("incidents", __name__)

STAFF = ("seguridad", "admin")


@bp.route("/reportar", methods=["GET", "POST"])
@login_required
def report():
    form = {"type": "phishing", "title": "", "description": "", "personal_data": "no_se",
            "ioc_sender": "", "ioc_url": ""}
    answers, anonymous = {}, False
    if request.method == "POST":
        form = {k: request.form.get(k, v if k == "personal_data" else "").strip() for k, v in form.items()}
        anonymous = request.form.get("anonymous") == "1"
        answers = {q[0]: request.form.get(f"g_{form['type']}_{q[0]}", "")
                   for q in content.GUIDED.get(form["type"], [])}
        answers = {k: v for k, v in answers.items() if v in content.GUIDED_ANSWERS}
        form["ioc_sender"], form["ioc_url"] = form["ioc_sender"][:200], form["ioc_url"][:500]
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
            suggested, _reasons = content.suggest_severity(form["type"], answers, form["personal_data"])
            inc = Incident(reporter=current_user, guided_json=json.dumps(answers), suggested_severity=suggested,
                           severity=suggested, anonymous=anonymous, ioc_domain=indicators.domain_of(
                               form["ioc_sender"], form["ioc_url"]), **form)
            db.session.add(inc)
            db.session.flush()
            audit("incidente_creado", f"#{inc.id} {inc.title}" + (" (anónimo)" if anonymous else ""),
                  incident=inc, anonymous=anonymous)
            saved, file_errors = uploads.save_files(request.files.getlist("evidence"), inc, current_user)
            if saved:
                audit("evidencia_adjunta", f"#{inc.id}: {saved} archivo(s)", incident=inc, anonymous=anonymous)
            notify.new_incident(inc)
            db.session.commit()
            alert = alerts.incident_alert(inc)
            if alert and not alert[0]:
                audit("alerta_fallida", f"#{inc.id}: {alert[1]}", incident=inc, anonymous=True)
                db.session.commit()
            for e in file_errors:
                flash(e, "err")
            flash("Incidente reportado. El encargado de seguridad lo revisará. Mientras tanto, sigue estos pasos.", "ok")
            return redirect(url_for("incidents.detail", incident_id=inc.id, nuevo=1))

    mine = Incident.query.filter_by(reporter_id=current_user.id).order_by(Incident.created_at.desc()).all()
    return render_template("incidents/report.html", form=form, mine=mine, answers=answers, anonymous=anonymous,
                           guided=content.GUIDED, guided_answers=content.GUIDED_ANSWERS), (
        400 if request.method == "POST" else 200)


@bp.route("/incidentes/<int:incident_id>")
@login_required
def detail(incident_id):
    inc = db.get_or_404(Incident, incident_id)
    if current_user.role not in STAFF and inc.reporter_id != current_user.id:
        abort(404)  # no revela la existencia de incidentes ajenos
    can_edit = current_user.role == "seguridad"
    events = inc.events.all() if current_user.role in STAFF else []
    notify.mark_incident_read(current_user, inc)
    db.session.commit()
    _sev, reasons = content.suggest_severity(inc.type, inc.guided, inc.personal_data)
    done = inc.playbook_done
    return render_template(
        "incidents/detail.html", inc=inc, can_edit=can_edit, events=events,
        analysts=_analysts() if can_edit else [], guide=content.GUIDES.get(inc.type),
        is_new=request.args.get("nuevo") == "1", sic=compliance.sic_status(inc) if inc.personal_data == "si" else None,
        can_upload=_can_upload(inc), max_files=uploads.MAX_PER_INCIDENT, can_see_evidence=_can_see_evidence(inc),
        can_talk=_can_see_evidence(inc), reasons=reasons, guided=content.GUIDED.get(inc.type, []),
        guided_answers=content.GUIDED_ANSWERS, related=indicators.related(inc) if current_user.role in STAFF else [],
        playbook=content.PLAYBOOKS.get(inc.type, []), done=done, progress=content.playbook_progress(inc.type, done),
    )


@bp.route("/incidentes/<int:incident_id>/comentarios", methods=["POST"])
@login_required
def add_comment(incident_id):
    inc = db.get_or_404(Incident, incident_id)
    if not _can_see(inc):
        abort(404)
    if not _can_see_evidence(inc):  # la administración de cuentas no participa en la conversación
        abort(403)
    body = request.form.get("body", "").strip()
    if not 2 <= len(body) <= 2000:
        flash("Escribe un mensaje de entre 2 y 2000 caracteres.", "err")
    else:
        db.session.add(Comment(incident=inc, user_id=current_user.id, body=body))
        if current_user.role == "seguridad" and inc.first_response_at is None:
            inc.first_response_at = utcnow()  # responder al empleado cuenta como primera atención
        is_reporter = current_user.id == inc.reporter_id
        audit("comentario", f"#{inc.id}: mensaje de {'quien reportó' if is_reporter else 'seguridad'}",
              incident=inc, anonymous=is_reporter and inc.anonymous)
        notify.new_comment(inc, current_user)
        notify.mark_incident_read(current_user, inc)  # quien actúa sobre el incidente ya lo vio
        db.session.commit()
    return redirect(url_for("incidents.detail", incident_id=inc.id) + "#conversacion")


@bp.route("/gestion/<int:incident_id>/playbook", methods=["POST"])
@roles_required("seguridad")
def update_playbook(incident_id):
    inc = db.get_or_404(Incident, incident_id)
    valid = {sid for _p, steps in content.PLAYBOOKS.get(inc.type, []) for sid, _t in steps}
    new = [s for s in request.form.getlist("step") if s in valid]
    old = set(inc.playbook_done)
    added, removed = [s for s in new if s not in old], [s for s in old if s not in new]
    if added or removed:
        inc.playbook_json = json.dumps(sorted(set(new)))
        if inc.first_response_at is None:
            inc.first_response_at = utcnow()
        for s in added:
            audit("paso_respuesta", f"#{inc.id}: ✓ {content.PLAYBOOK_STEPS[s]}", incident=inc)
        for s in removed:
            audit("paso_respuesta", f"#{inc.id}: se desmarcó «{content.PLAYBOOK_STEPS[s]}»", incident=inc)
        notify.mark_incident_read(current_user, inc)
        db.session.commit()
        flash("Guía de respuesta actualizada.", "ok")
    return redirect(url_for("incidents.detail", incident_id=inc.id) + "#guia-respuesta")


@bp.route("/notificaciones", methods=["GET", "POST"])
@login_required
def notifications():
    if request.method == "POST":
        Notification.query.filter_by(user_id=current_user.id, read_at=None).update({"read_at": utcnow()})
        db.session.commit()
        return redirect(url_for("incidents.notifications"))
    items = (Notification.query.filter_by(user_id=current_user.id)
             .order_by(Notification.created_at.desc()).limit(50).all())
    return render_template("incidents/notifications.html", items=items)


@bp.route("/gestion/indicadores.csv")
@roles_required(*STAFF)
def export_indicators():
    """Remitentes, dominios y enlaces reportados (sin descartados) para bloquearlos en el correo o el antivirus."""
    rows = {}
    for i in Incident.query.filter(Incident.status != "descartado").order_by(Incident.created_at).all():
        for kind, value in (("remitente", i.ioc_sender), ("dominio", i.ioc_domain), ("enlace", i.ioc_url)):
            if value:
                r = rows.setdefault((kind, value.lower()), {"n": 0, "first": i.created_at, "ids": []})
                r["n"] += 1
                r["ids"].append(f"#{i.id}")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Tipo", "Valor", "Reportes", "Primera vez (UTC)", "Incidentes"])
    for (kind, value), r in sorted(rows.items(), key=lambda kv: -kv[1]["n"]):
        w.writerow([kind, _safe(value), r["n"], r["first"].isoformat(timespec="minutes"), " ".join(r["ids"])])
    audit("exportacion_indicadores", "Exportó indicadores de compromiso")
    db.session.commit()
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=indicadores.csv"})


def _can_see(inc):
    return current_user.role in STAFF or inc.reporter_id == current_user.id


def _can_see_evidence(inc):
    # La evidencia puede tener datos personales: solo quien reportó y seguridad (no la administración de cuentas).
    return current_user.role == "seguridad" or inc.reporter_id == current_user.id


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
    if not _can_see_evidence(att.incident):
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
    recent = Incident.query.filter(Incident.created_at >= utcnow() - timedelta(days=indicators.CAMPAIGN_DAYS)).all()
    return render_template(
        "incidents/manage.html", page=page, f=f, can_edit=current_user.role == "seguridad", analysts=_analysts(),
        campaigns=indicators.campaigns(recent), progress=lambda i: content.playbook_progress(i.type, i.playbook_done),
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
    root_cause = request.form.get("root_cause", inc.root_cause).strip()[:2000]
    lesson = request.form.get("lesson", inc.lesson).strip()[:2000]
    ioc_sender = request.form.get("ioc_sender", inc.ioc_sender).strip()[:200]
    ioc_url = request.form.get("ioc_url", inc.ioc_url).strip()[:500]

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
    if root_cause != inc.root_cause or lesson != inc.lesson:
        changes.append("lecciones aprendidas actualizadas")
    if ioc_sender != inc.ioc_sender or ioc_url != inc.ioc_url:
        changes.append("indicadores actualizados")

    if changes:
        # Lo que le interesa a quien reportó, calculado antes de aplicar los cambios.
        reporter_changes = []
        if status != inc.status:
            reporter_changes.append(f"estado «{STATES[status]}»")
        if notes != inc.notes and notes:
            reporter_changes.append("nueva respuesta de seguridad")
        inc.status, inc.severity, inc.notes, inc.assigned_to_id = status, severity, notes, assigned_id
        inc.personal_data = personal
        inc.root_cause, inc.lesson = root_cause, lesson
        inc.ioc_sender, inc.ioc_url = ioc_sender, ioc_url
        inc.ioc_domain = indicators.domain_of(ioc_sender, ioc_url)
        if reporter_changes:
            notify.incident_updated(inc, ", ".join(reporter_changes))
        if status == "resuelto" and not (root_cause and lesson):
            flash("Recomendado: registra la causa y la medida preventiva (lecciones aprendidas) al resolver.", "warn")
        if "sic_reported_at" in request.form:
            inc.sic_reported_at = sic_date
        if inc.first_response_at is None and (status != "reportado" or assigned_id or notes):
            inc.first_response_at = utcnow()
        if status in CLOSED_STATES:
            inc.resolved_at = inc.resolved_at or utcnow()
        else:
            inc.resolved_at = None
        audit("incidente_actualizado", f"#{inc.id}: " + "; ".join(changes), incident=inc)
        notify.mark_incident_read(current_user, inc)
        db.session.commit()
        flash(f"Incidente #{inc.id} actualizado.", "ok")
    else:
        flash("No había cambios que guardar.", "ok")
    return redirect(safe_next(request.form.get("next", ""), url_for("incidents.manage")))


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
            i.id, fmt(i.created_at), TYPES[i.type], _safe(i.title), i.reporter_name,
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
    tasks = ActionItem.query.all()
    today = utcnow().date()
    return render_template(
        "incidents/dashboard.html", r=risk.compute(), sla_hours=settings.sla_hours(), delta=followup.risk_delta(),
        reminders=followup.reminders(), tasks={"total": len(tasks), "done": sum(1 for t in tasks if t.done_at),
                                                "overdue": sum(1 for t in tasks if t.is_overdue(today))})


@bp.route("/afiche")
@roles_required(*STAFF)
def poster():
    """Afiche imprimible con un QR al formulario de reporte, para pegar en la oficina."""
    import segno

    link = url_for("incidents.report", _external=True)
    if current_app.config["SESSION_COOKIE_SECURE"] and link.startswith("http://"):
        link = "https://" + link[len("http://"):]
    qr = segno.make(link, error="m").svg_data_uri(scale=10, border=2, dark="#10222B")
    return render_template("incidents/poster.html", link=link, qr=qr)


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
