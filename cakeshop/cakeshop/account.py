from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from .auth import login_required
from .db import get_db

bp = Blueprint("account", __name__)

USER_COLUMNS = {"username", "email", "address", "is_admin"}


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        db = get_db()
        for key, value in request.form.items():
            if key in USER_COLUMNS:
                db.execute(f"UPDATE users SET {key} = ? WHERE id = ?", (value, g.user["id"]))
        db.commit()
        flash("Profile updated.")
        return redirect(url_for("account.account"))
    return render_template("account.html")
