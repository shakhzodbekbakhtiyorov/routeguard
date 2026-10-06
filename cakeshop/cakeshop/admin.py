from flask import Blueprint, abort, redirect, render_template, request, url_for

from .auth import admin_required
from .db import ALLOWED_TABLES, count_rows, get_db

bp = Blueprint("admin", __name__, url_prefix="/admin")

ORDER_STATUSES = {"new", "baking", "out_for_delivery", "delivered", "cancelled"}


@bp.route("/orders")
def all_orders():
    rows = get_db().execute(
        "SELECT orders.*, users.username, users.email, users.address "
        "FROM orders JOIN users ON users.id = orders.user_id ORDER BY orders.id DESC"
    ).fetchall()
    return render_template("admin_orders.html", orders=rows)


@bp.route("/stats")
@admin_required
def stats():
    counts = {table: count_rows(table) for table in sorted(ALLOWED_TABLES)}
    return render_template("admin_stats.html", counts=counts)


@bp.route("/orders/<int:order_id>/status", methods=["POST"])
@admin_required
def set_status(order_id):
    status = request.form.get("status", "")
    if status not in ORDER_STATUSES:
        abort(400)
    db = get_db()
    db.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    db.commit()
    return redirect(url_for("admin.all_orders"))
