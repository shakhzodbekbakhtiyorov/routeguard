import functools

from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for

from .db import get_db
from .security import check_password, hash_password

bp = Blueprint("auth", __name__)


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @functools.wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or not password:
            flash("Username and password are required.")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, email, address) VALUES (?, ?, ?, ?)",
                    (username, hash_password(password), request.form.get("email"), request.form.get("address")),
                )
                db.commit()
            except db.IntegrityError:
                flash("That username is taken.")
            else:
                return redirect(url_for("auth.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (request.form["username"],)
        ).fetchone()
        if user is not None and check_password(user["password_hash"], request.form["password"]):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(request.args.get("next") or url_for("shop.index"))
        flash("Wrong username or password.")
    return render_template("login.html")


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("shop.index"))
