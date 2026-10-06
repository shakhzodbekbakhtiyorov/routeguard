import os

from flask import Flask

from . import db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY="cakeshop-secret-2024",
        DATABASE=os.path.join(app.instance_path, "cakeshop.sqlite"),
        IMAGE_DIR=os.path.join(app.root_path, "static", "cakes"),
        INVOICE_DIR=os.path.join(app.instance_path, "invoices"),
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["INVOICE_DIR"], exist_ok=True)

    db.init_app(app)

    from . import account, admin, auth, orders, shop

    for blueprint in (auth.bp, shop.bp, orders.bp, admin.bp, account.bp):
        app.register_blueprint(blueprint)

    return app
