import json

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user

from datetime import date, timedelta

from flask import abort

from . import content, followup, notify
from .extensions import db
from .models import ActionItem, Assessment, ReminderLog, User, utcnow
from .security import audit, roles_required, safe_next

STAFF = ("seguridad", "admin")

bp = Blueprint("assessment", __name__)


@bp.route("/evaluacion")
@roles_required("seguridad", "admin")
def overview():
    history = Assessment.query.order_by(Assessment.created_at.desc(), Assessment.id.desc()).all()
    latest = history[0] if history else None
    plan = content.action_plan(latest.answers) if latest else []
    by_area = {}
    if latest:
        for qid, area, _cis, weight, *_ in content.QUESTIONS:
            got, tot = by_area.get(area, (0, 0))
            by_area[area] = (got + weight * content.ANSWER_VALUE.get(latest.answers.get(qid, "no_se"), 0), tot + weight)
    areas = [(a, round(g / t * 100)) for a, (g, t) in by_area.items()]
    tasks = ActionItem.query.order_by(ActionItem.done_at.isnot(None), ActionItem.due_date).all()
    open_by_q = {t.question_id: t for t in tasks if t.done_at is None}
    owners = User.query.filter(User.role.in_(STAFF), User.is_active_flag.is_(True)).order_by(User.full_name).all()
    return render_template("assessment/overview.html", latest=latest, history=history, plan=plan, areas=areas,
                           n_questions=len(content.QUESTIONS), level=content.maturity_level, tasks=tasks,
                           open_by_q=open_by_q, owners=owners, today=utcnow().date(),
                           default_due=(utcnow().date() + timedelta(days=30)).isoformat())


@bp.route("/evaluacion/tareas", methods=["POST"])
@roles_required(*STAFF)
def create_task():
    qid = request.form.get("question_id", "")
    question = next((q for q in content.QUESTIONS if q[0] == qid), None)
    owner = db.session.get(User, int(request.form.get("owner_id", "0") or 0))
    try:
        due = date.fromisoformat(request.form.get("due_date", ""))
    except ValueError:
        due = None
    if not question or not owner or owner.role not in STAFF or not owner.is_active:
        abort(400)
    if not due or due < utcnow().date():
        flash("Elige una fecha límite de hoy en adelante.", "err")
        return redirect(url_for("assessment.overview") + "#plan")
    title = question[5].split(". ")[0].rstrip(".")
    task = ActionItem(question_id=qid, title=title, owner_id=owner.id, due_date=due, created_by_id=current_user.id)
    db.session.add(task)
    audit("tarea_creada", f"«{title}» → {owner.full_name}, vence {due.strftime('%d/%m/%Y')}")
    if owner.id != current_user.id:
        db.session.add(notify.Notification(user_id=owner.id, text=f"Te asignaron una tarea del plan de acción: {title} "
                                                                   f"(vence {due.strftime('%d/%m/%Y')})"))
    db.session.commit()
    flash("Tarea asignada.", "ok")
    return redirect(url_for("assessment.overview") + "#tareas")


@bp.route("/evaluacion/tareas/<int:task_id>", methods=["POST"])
@roles_required(*STAFF)
def update_task(task_id):
    task = db.get_or_404(ActionItem, task_id)
    action = request.form.get("action")
    if action == "done" and task.done_at is None:
        task.done_at = utcnow()
        audit("tarea_completada", f"«{task.title}»")
        flash("Tarea completada. Cuando termines varias, actualiza la autoevaluación para ver subir la madurez.", "ok")
    elif action == "reopen" and task.done_at is not None:
        task.done_at = None
        audit("tarea_reabierta", f"«{task.title}»")
    elif action == "delete":
        audit("tarea_eliminada", f"«{task.title}»")
        db.session.delete(task)
    else:
        abort(400)
    db.session.commit()
    return redirect(url_for("assessment.overview") + "#tareas")


@bp.route("/recordatorios/<key>", methods=["POST"])
@roles_required(*STAFF)
def reminder_done(key):
    item = next((r for r in content.REMINDERS if r[0] == key and r[3] == "manual"), None)
    if not item:
        abort(404)
    db.session.add(ReminderLog(key=key, user_id=current_user.id))
    audit("recordatorio_hecho", item[1])
    db.session.commit()
    flash(f"Registrado: {item[1].lower()}. Te lo recordaremos en {item[2]} días.", "ok")
    return redirect(safe_next(request.form.get("next", ""), url_for("incidents.dashboard")))


@bp.route("/evaluacion/nueva", methods=["GET", "POST"])
@roles_required("seguridad", "admin")
def new():
    last = Assessment.query.order_by(Assessment.created_at.desc(), Assessment.id.desc()).first()
    answers = last.answers if last else {}
    if request.method == "POST":
        answers = {qid: request.form.get(qid, "") for qid in content.QUESTION_IDS}
        missing = [qid for qid, a in answers.items() if a not in content.ANSWERS]
        if missing:
            flash(f"Responde todas las preguntas (faltan {len(missing)}). Si no sabes, elige «No sé».", "err")
        else:
            score = content.maturity_score(answers)
            a = Assessment(user_id=current_user.id, answers_json=json.dumps(answers), score=score)
            db.session.add(a)
            audit("autoevaluacion", f"Madurez {score}/100")
            db.session.commit()
            flash(f"Autoevaluación guardada: madurez {score} de 100. Este es tu plan de acción.", "ok")
            return redirect(url_for("assessment.overview"))
    groups = {}
    for q in content.QUESTIONS:
        groups.setdefault(q[1], []).append(q)
    return render_template("assessment/form.html", groups=groups, answers=answers), (
        400 if request.method == "POST" else 200)
