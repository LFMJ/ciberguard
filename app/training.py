from flask import Blueprint, flash, render_template, request
from flask_login import current_user, login_required

from . import content, risk
from .extensions import db
from .models import QuizAttempt, utcnow
from .security import audit, roles_required

bp = Blueprint("training", __name__)


@bp.route("/capacitacion", methods=["GET", "POST"])
@login_required
def quiz():
    mine = QuizAttempt.query.filter_by(user_id=current_user.id).order_by(QuizAttempt.created_at.desc()).limit(5).all()
    if request.method == "POST":
        picks = {}
        for q in content.QUIZ:
            raw = request.form.get(q["id"], "")
            picks[q["id"]] = int(raw) if raw.isdigit() and int(raw) < len(q["options"]) else None
        if any(v is None for v in picks.values()):
            flash("Responde todas las preguntas antes de enviar.", "err")
            return render_template("training/quiz.html", quiz=content.QUIZ, picks=picks, mine=mine), 400
        correct = sum(1 for q in content.QUIZ if picks[q["id"]] == q["answer"])
        attempt = QuizAttempt(user_id=current_user.id, correct=correct, total=len(content.QUIZ))
        db.session.add(attempt)
        audit("capacitacion", f"Microcapacitación: {correct}/{len(content.QUIZ)}")
        db.session.commit()
        return render_template("training/result.html", quiz=content.QUIZ, picks=picks, attempt=attempt)
    return render_template("training/quiz.html", quiz=content.QUIZ, picks={}, mine=mine)


@bp.route("/capacitacion/equipo")
@roles_required("seguridad", "admin")
def team():
    return render_template("training/team.html", t=risk.training_summary(utcnow()), window=risk.TRAINING_WINDOW_DAYS)
