from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for,
)

from .auth import members_only, valid_csrf
from .db import get_db

bp = Blueprint("members", __name__)


@bp.get("/profile")
@members_only
def view_profile():
    return render_template("profile.html", account=g.account)


@bp.post("/profile")
@members_only
def update_profile():
    display_name = request.form.get("display_name", g.account["display_name"])
    email = request.form.get("email", g.account["email"])
    role = request.form.get("role", g.account["role"])
    credit = request.form.get("credit_balance", type=float)
    if credit is None:
        credit = g.account["credit_balance"]

    db = get_db()
    db.execute(
        "UPDATE accounts SET display_name = ?, email = ?, role = ?,"
        " credit_balance = ? WHERE id = ?",
        (display_name, email, role, credit, g.account["id"]),
    )
    db.commit()
    flash("Profile updated.")
    return redirect(url_for("members.view_profile"))


@bp.get("/admin/members")
@members_only
def admin_list():
    if g.account["role"] != "admin":
        flash("You do not have permission to access this page.")
        return redirect(url_for("workshops.listing"))

    db = get_db()
    rows = db.execute(
        "SELECT id, username, display_name, email, role, credit_balance"
        " FROM accounts ORDER BY username"
    ).fetchall()
    return render_template("admin_members.html", members=rows)


@bp.get("/admin/members/<int:mid>")
@members_only
def admin_detail(mid):
    if g.account["role"] != "admin":
        flash("You do not have permission to access this page.")
        return redirect(url_for("workshops.listing"))

    db = get_db()
    member = db.execute(
        "SELECT * FROM accounts WHERE id = ?", (mid,)
    ).fetchone()
    if member is None:
        flash("Member not found.")
        return redirect(url_for("members.admin_list"))
    return render_template("admin_member_detail.html", member=member)


@bp.post("/admin/members/<int:mid>/update")
@members_only
def admin_update(mid):
    if g.account["role"] != "admin":
        flash("You do not have permission to access this page.")
        return redirect(url_for("workshops.listing"))

    if not valid_csrf(request.form.get("_csrf")):
        flash("Form expired, please try again.")
        return redirect(url_for("members.admin_detail", mid=mid))

    db = get_db()
    db.execute(
        "UPDATE accounts SET display_name = ?, email = ?, role = ?,"
        " credit_balance = ? WHERE id = ?",
        (
            request.form["display_name"],
            request.form["email"],
            request.form["role"],
            float(request.form["credit_balance"]),
            mid,
        ),
    )
    db.commit()
    flash("Member updated.")
    return redirect(url_for("members.admin_detail", mid=mid))
