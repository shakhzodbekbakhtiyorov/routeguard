from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for,
)

from .auth import members_only, staff_only, valid_csrf
from .db import get_db

bp = Blueprint("workshops", __name__)


@bp.get("/")
def listing():
    db = get_db()
    rows = db.execute(
        "SELECT w.*, a.display_name AS organiser"
        " FROM workshops w JOIN accounts a ON w.created_by = a.id"
        " ORDER BY w.scheduled_at"
    ).fetchall()
    return render_template("workshop_list.html", workshops=rows)


@bp.get("/<int:wid>")
def detail(wid):
    db = get_db()
    workshop = db.execute(
        "SELECT w.*, a.display_name AS organiser"
        " FROM workshops w JOIN accounts a ON w.created_by = a.id"
        " WHERE w.id = ?",
        (wid,),
    ).fetchone()
    if workshop is None:
        flash("Workshop not found.")
        return redirect(url_for("workshops.listing"))

    booked = db.execute(
        "SELECT COALESCE(SUM(seats), 0) FROM reservations"
        " WHERE workshop_id = ? AND status = 'confirmed'",
        (wid,),
    ).fetchone()[0]
    remaining = workshop["capacity"] - booked
    return render_template(
        "workshop_detail.html", workshop=workshop, remaining=remaining,
    )


@bp.get("/create")
@staff_only
def create_form():
    return render_template("workshop_form.html", workshop=None)


@bp.post("/create")
@staff_only
def create():
    if not valid_csrf(request.form.get("_csrf")):
        flash("Form expired, please try again.")
        return redirect(url_for("workshops.create_form"))

    title = request.form["title"].strip()
    description = request.form.get("description", "").strip()
    capacity = int(request.form["capacity"])
    price = float(request.form["price_per_seat"])
    scheduled = request.form["scheduled_at"]

    if not title or capacity < 1 or price < 0:
        flash("Please fill in all required fields correctly.")
        return redirect(url_for("workshops.create_form"))

    db = get_db()
    db.execute(
        "INSERT INTO workshops"
        " (title, description, capacity, price_per_seat, scheduled_at, created_by)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (title, description, capacity, price, scheduled, g.account["id"]),
    )
    db.commit()
    flash("Workshop created.")
    return redirect(url_for("workshops.listing"))


@bp.get("/<int:wid>/edit")
@staff_only
def edit_form(wid):
    db = get_db()
    workshop = db.execute(
        "SELECT * FROM workshops WHERE id = ?", (wid,)
    ).fetchone()
    if workshop is None:
        flash("Workshop not found.")
        return redirect(url_for("workshops.manage"))
    return render_template("workshop_form.html", workshop=workshop)


@bp.post("/<int:wid>/edit")
@staff_only
def edit(wid):
    if not valid_csrf(request.form.get("_csrf")):
        flash("Form expired, please try again.")
        return redirect(url_for("workshops.edit_form", wid=wid))

    db = get_db()
    db.execute(
        "UPDATE workshops"
        " SET title = ?, description = ?, capacity = ?,"
        " price_per_seat = ?, scheduled_at = ?"
        " WHERE id = ?",
        (
            request.form["title"].strip(),
            request.form.get("description", "").strip(),
            int(request.form["capacity"]),
            float(request.form["price_per_seat"]),
            request.form["scheduled_at"],
            wid,
        ),
    )
    db.commit()
    flash("Workshop updated.")
    return redirect(url_for("workshops.manage"))


@bp.get("/manage")
@members_only
def manage():
    db = get_db()
    all_workshops = db.execute(
        "SELECT w.*, a.display_name AS organiser"
        " FROM workshops w JOIN accounts a ON w.created_by = a.id"
        " ORDER BY w.scheduled_at"
    ).fetchall()
    all_reservations = db.execute(
        "SELECT r.*, a.display_name AS member_name, w.title AS workshop_title"
        " FROM reservations r"
        " JOIN accounts a ON r.owner_id = a.id"
        " JOIN workshops w ON r.workshop_id = w.id"
        " ORDER BY r.reserved_at DESC"
    ).fetchall()
    return render_template(
        "workshop_manage.html",
        workshops=all_workshops,
        reservations=all_reservations,
    )


@bp.post("/<int:wid>/book")
@members_only
def book(wid):
    db = get_db()
    workshop = db.execute(
        "SELECT * FROM workshops WHERE id = ?", (wid,)
    ).fetchone()
    if workshop is None:
        flash("Workshop not found.")
        return redirect(url_for("workshops.listing"))

    seats = request.form.get("seats", type=int) or 1
    total_cost = request.form.get("total_cost", type=float)

    db.execute(
        "INSERT INTO reservations"
        " (workshop_id, owner_id, seats, total_cost, status)"
        " VALUES (?, ?, ?, ?, 'confirmed')",
        (wid, g.account["id"], seats, total_cost),
    )
    db.commit()
    flash("Booking confirmed!")
    return redirect(url_for("bookings.my_bookings"))
