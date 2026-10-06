import os
import subprocess

from flask import Blueprint, abort, current_app, g, render_template, request, send_file

from .auth import login_required
from .db import get_db

bp = Blueprint("orders", __name__)


@bp.route("/orders")
@login_required
def my_orders():
    rows = get_db().execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (g.user["id"],)
    ).fetchall()
    return render_template("orders.html", orders=rows)


@bp.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    order = get_db().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if order is None:
        abort(404)
    return render_template("order.html", order=order)


def invoice_date():
    result = subprocess.run(["date", "+%Y-%m-%d"], capture_output=True, text=True, check=False)
    return result.stdout.strip()


@bp.route("/orders/<int:order_id>/invoice")
@login_required
def invoice(order_id):
    order = get_db().execute(
        "SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, g.user["id"])
    ).fetchone()
    if order is None:
        abort(404)
    fmt = request.args.get("format", "txt")
    path = os.path.join(current_app.config["INVOICE_DIR"], f"order_{order_id}.{fmt}")
    os.system(f"echo 'Order {order_id} | total {order['total']} UZS | {invoice_date()}' > {path}")
    return send_file(path)
