from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for,
)

from .auth import members_only, valid_csrf
from .db import get_db, verify_reservation_owner

bp = Blueprint("bookings", __name__)


@bp.get("/")
@members_only
def my_bookings():
    db = get_db()
    rows = db.execute(
        "SELECT r.*, w.title AS workshop_title, w.scheduled_at"
        " FROM reservations r"
        " JOIN workshops w ON r.workshop_id = w.id"
        " WHERE r.owner_id = ?"
        " ORDER BY r.reserved_at DESC",
        (g.account["id"],),
    ).fetchall()
    return render_template("booking_list.html", bookings=rows)


@bp.get("/<int:rid>")
@members_only
def detail(rid):
    db = get_db()
    reservation = db.execute(
        "SELECT r.*, w.title AS workshop_title,"
        " w.scheduled_at, w.price_per_seat"
        " FROM reservations r"
        " JOIN workshops w ON r.workshop_id = w.id"
        " WHERE r.id = ?",
        (rid,),
    ).fetchone()
    if reservation is None:
        flash("Booking not found.")
        return redirect(url_for("bookings.my_bookings"))

    notes = db.execute(
        "SELECT n.*, a.display_name AS author_name"
        " FROM notes n JOIN accounts a ON n.author_id = a.id"
        " WHERE n.reservation_id = ?"
        " ORDER BY n.created_at",
        (rid,),
    ).fetchall()
    return render_template(
        "booking_detail.html", booking=reservation, notes=notes,
    )


@bp.post("/<int:rid>/cancel")
@members_only
def cancel(rid):
    db = get_db()
    db.execute(
        "UPDATE reservations SET status = 'cancelled' WHERE id = ?",
        (rid,),
    )
    db.commit()
    flash("Booking cancelled.")
    return redirect(url_for("bookings.my_bookings"))


@bp.post("/<int:rid>/note")
@members_only
def add_note(rid):
    if not valid_csrf(request.form.get("_csrf")):
        flash("Form expired, please try again.")
        return redirect(url_for("bookings.detail", rid=rid))

    if not verify_reservation_owner(rid, g.account["id"]):
        flash("You can only add notes to your own bookings.")
        return redirect(url_for("bookings.my_bookings"))

    body = request.form.get("body", "").strip()
    if not body:
        flash("Note cannot be empty.")
        return redirect(url_for("bookings.detail", rid=rid))

    db = get_db()
    db.execute(
        "INSERT INTO notes (reservation_id, author_id, body)"
        " VALUES (?, ?, ?)",
        (rid, g.account["id"], body),
    )
    db.commit()
    flash("Note added.")
    return redirect(url_for("bookings.detail", rid=rid))


@bp.get("/<int:rid>/receipt")
def receipt(rid):
    db = get_db()
    reservation = db.execute(
        "SELECT r.*, w.title AS workshop_title,"
        " w.scheduled_at, w.price_per_seat,"
        " a.display_name AS member_name, a.email AS member_email"
        " FROM reservations r"
        " JOIN workshops w ON r.workshop_id = w.id"
        " JOIN accounts a ON r.owner_id = a.id"
        " WHERE r.id = ?",
        (rid,),
    ).fetchone()
    if reservation is None:
        flash("Receipt not found.")
        return redirect(url_for("auth.login_page"))
    return render_template("booking_receipt.html", booking=reservation)
