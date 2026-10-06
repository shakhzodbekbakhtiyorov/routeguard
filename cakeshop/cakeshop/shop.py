import base64
import os
import pickle

from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    make_response,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    send_from_directory,
    url_for,
)
from werkzeug.utils import secure_filename

from .auth import login_required
from .db import get_db, search_products

bp = Blueprint("shop", __name__)


@bp.route("/")
def index():
    products = get_db().execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products)


@bp.route("/search")
def search():
    q = request.args.get("q", "")
    results = search_products(q)
    return render_template("search.html", q=q, results=results)


@bp.route("/product/<int:product_id>")
def product(product_id):
    db = get_db()
    item = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if item is None:
        abort(404)
    reviews = db.execute("SELECT * FROM reviews WHERE product_id = ?", (product_id,)).fetchall()
    return render_template("product.html", product=item, reviews=reviews)


@bp.route("/product/<int:product_id>/review", methods=["POST"])
@login_required
def add_review(product_id):
    db = get_db()
    db.execute(
        "INSERT INTO reviews (product_id, username, body) VALUES (?, ?, ?)",
        (product_id, g.user["username"], request.form["body"]),
    )
    db.commit()
    return redirect(url_for("shop.product", product_id=product_id))


@bp.route("/image")
def cake_image():
    filename = request.args.get("name", "")
    return send_file(os.path.join(current_app.config["IMAGE_DIR"], filename))


@bp.route("/thumbnail")
def cake_thumbnail():
    filename = secure_filename(request.args.get("name", ""))
    return send_from_directory(current_app.config["IMAGE_DIR"], filename)


@bp.route("/greeting")
def greeting():
    name = request.args.get("name", "friend")
    return render_template_string("<p>Happy birthday, {{ name }}!</p>", name=name)


@bp.route("/cake-message/preview")
def preview_message():
    text = request.args.get("text", "")
    template = "<div class='cake-top'>" + text + "</div>"
    return render_template_string(template)


def _load_cart():
    raw = request.cookies.get("cart")
    if not raw:
        return {}
    return pickle.loads(base64.b64decode(raw))


def _dump_cart(cart):
    return base64.b64encode(pickle.dumps(cart)).decode()


@bp.route("/cart")
def view_cart():
    cart = _load_cart()
    db = get_db()
    items = []
    for product_id, qty in cart.items():
        row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if row is not None:
            items.append({"product": row, "quantity": qty})
    return render_template("cart.html", items=items)


@bp.route("/cart/add", methods=["POST"])
def add_to_cart():
    cart = _load_cart()
    product_id = int(request.form["product_id"])
    cart[product_id] = cart.get(product_id, 0) + 1
    resp = make_response(redirect(url_for("shop.view_cart")))
    resp.set_cookie("cart", _dump_cart(cart))
    return resp


@bp.route("/checkout", methods=["POST"])
@login_required
def checkout():
    product_id = int(request.form["product_id"])
    quantity = int(request.form.get("quantity", 1))
    price = int(request.form["price"])
    total = price * quantity
    db = get_db()
    cur = db.execute(
        "INSERT INTO orders (user_id, product_id, quantity, total, message, note) VALUES (?, ?, ?, ?, ?, ?)",
        (
            g.user["id"],
            product_id,
            quantity,
            total,
            request.form.get("message", ""),
            request.form.get("note", ""),
        ),
    )
    db.commit()
    return redirect(url_for("orders.order_detail", order_id=cur.lastrowid))
