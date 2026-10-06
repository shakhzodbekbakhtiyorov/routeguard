import sqlite3

from flask import current_app, g
from werkzeug.security import generate_password_hash


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
    return g.db


def close_connection(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()

    db.executescript(
        """
        DROP TABLE IF EXISTS notes;
        DROP TABLE IF EXISTS reservations;
        DROP TABLE IF EXISTS workshops;
        DROP TABLE IF EXISTS accounts;

        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            passhash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            email TEXT,
            role TEXT NOT NULL DEFAULT 'member',
            credit_balance REAL NOT NULL DEFAULT 0.0
        );

        CREATE TABLE workshops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            capacity INTEGER NOT NULL,
            price_per_seat REAL NOT NULL,
            scheduled_at TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            FOREIGN KEY (created_by) REFERENCES accounts(id)
        );

        CREATE TABLE reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workshop_id INTEGER NOT NULL,
            owner_id INTEGER NOT NULL,
            seats INTEGER NOT NULL,
            total_cost REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'confirmed',
            reserved_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (workshop_id) REFERENCES workshops(id),
            FOREIGN KEY (owner_id) REFERENCES accounts(id)
        );

        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reservation_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (reservation_id) REFERENCES reservations(id),
            FOREIGN KEY (author_id) REFERENCES accounts(id)
        );
        """
    )

    users = [
        ("admin", generate_password_hash("admin123"), "Administrator",
         "admin@workshop.local", "admin", 200.0),
        ("alice", generate_password_hash("alice123"), "Alice Martin",
         "alice@example.com", "member", 75.0),
        ("bob", generate_password_hash("bob123"), "Bob Taylor",
         "bob@example.com", "member", 60.0),
    ]
    for u in users:
        db.execute(
            "INSERT INTO accounts"
            " (username, passhash, display_name, email, role, credit_balance)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            u,
        )

    admin_id = db.execute(
        "SELECT id FROM accounts WHERE username = ?", ("admin",)
    ).fetchone()["id"]

    seed_workshops = [
        ("Intro to Woodworking",
         "Learn the basics of woodworking with hand tools.",
         12, 25.00, "2026-11-15 10:00", admin_id),
        ("Pottery Fundamentals",
         "Hands-on pottery wheel and glazing techniques.",
         8, 35.00, "2026-11-22 14:00", admin_id),
        ("Screen Printing 101",
         "Create your own screen-printed designs on fabric.",
         10, 30.00, "2026-12-01 11:00", admin_id),
        ("Leathercraft Basics",
         "Cut, stitch, and finish a small leather project.",
         6, 40.00, "2026-12-10 09:30", admin_id),
    ]
    for w in seed_workshops:
        db.execute(
            "INSERT INTO workshops"
            " (title, description, capacity, price_per_seat, scheduled_at, created_by)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            w,
        )

    alice_id = db.execute(
        "SELECT id FROM accounts WHERE username = ?", ("alice",)
    ).fetchone()["id"]
    bob_id = db.execute(
        "SELECT id FROM accounts WHERE username = ?", ("bob",)
    ).fetchone()["id"]

    seed_reservations = [
        (1, alice_id, 2, 50.00, "confirmed"),
        (2, bob_id, 1, 35.00, "confirmed"),
        (3, alice_id, 3, 90.00, "confirmed"),
        (4, bob_id, 2, 80.00, "confirmed"),
    ]
    for r in seed_reservations:
        db.execute(
            "INSERT INTO reservations"
            " (workshop_id, owner_id, seats, total_cost, status)"
            " VALUES (?, ?, ?, ?, ?)",
            r,
        )

    seed_notes = [
        (1, alice_id, "Looking forward to this one!"),
        (2, bob_id, "Do we need to bring aprons?"),
    ]
    for n in seed_notes:
        db.execute(
            "INSERT INTO notes (reservation_id, author_id, body)"
            " VALUES (?, ?, ?)",
            n,
        )

    db.commit()


def verify_reservation_owner(reservation_id, account_id):
    db = get_db()
    row = db.execute(
        "SELECT id FROM reservations WHERE id = ? AND owner_id = ?",
        (reservation_id, account_id),
    ).fetchone()
    return row is not None
