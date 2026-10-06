import functools
import secrets

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash

from .db import get_db

bp = Blueprint("auth", __name__)


@bp.before_app_request
def load_signed_in_account():
    account_id = session.get("account_id")
    if account_id is None:
        g.account = None
    else:
        g.account = get_db().execute(
            "SELECT * FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()


@bp.before_app_request
def provide_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    g.csrf_token = session["_csrf"]


def members_only(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.account is None:
            flash("Please sign in to continue.")
            return redirect(url_for("auth.login_page"))
        return view(**kwargs)
    return wrapped_view


def staff_only(view):
    @functools.wraps(view)
    def check_role(**kwargs):
        if g.account["role"] not in ("staff", "admin"):
            flash("You do not have permission to access this page.")
            return redirect(url_for("workshops.listing"))
        return view(**kwargs)
    return members_only(check_role)


def valid_csrf(token):
    return token is not None and token == session.get("_csrf")


@bp.get("/login")
def login_page():
    return render_template("login.html")


@bp.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not valid_csrf(request.form.get("_csrf")):
        flash("Form expired, please try again.")
        return redirect(url_for("auth.login_page"))

    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE username = ?", (username,)
    ).fetchone()

    if account is None or not check_password_hash(account["passhash"], password):
        flash("Invalid username or password.")
        return redirect(url_for("auth.login_page"))

    session.clear()
    session["account_id"] = account["id"]
    session["account_role"] = account["role"]
    flash("Welcome back, " + account["display_name"] + "!")
    return redirect(url_for("workshops.listing"))


@bp.get("/logout")
def logout():
    session.clear()
    flash("You have been signed out.")
    return redirect(url_for("auth.login_page"))
