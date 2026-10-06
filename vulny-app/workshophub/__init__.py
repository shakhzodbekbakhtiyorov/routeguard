import os

import click
from flask import Flask, redirect, url_for


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET", os.urandom(32).hex()),
        DATABASE=os.path.join(app.instance_path, "workshophub.sqlite"),
    )

    if test_config is not None:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from . import db

    app.teardown_appcontext(db.close_connection)

    @click.command("init-db")
    def init_db_command():
        db.init_db()
        click.echo("Database initialised.")

    app.cli.add_command(init_db_command)

    from . import auth, workshops, bookings, members

    app.register_blueprint(auth.bp)
    app.register_blueprint(workshops.bp, url_prefix="/workshops")
    app.register_blueprint(bookings.bp, url_prefix="/bookings")
    app.register_blueprint(members.bp)

    @app.route("/")
    def index():
        return redirect(url_for("workshops.listing"))

    return app
