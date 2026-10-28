import json

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user

from . import content
from .extensions import db
from .models import Assessment
from .security import audit, roles_required

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
    return render_template("assessment/overview.html", latest=latest, history=history, plan=plan, areas=areas,
                           n_questions=len(content.QUESTIONS),
                           level=content.maturity_level)


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
