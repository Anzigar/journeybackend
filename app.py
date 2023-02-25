from flask import Flask
from flask_migrate import Migrate
from models import db
from item import ma
from routes import api_bp

# initialize app
app = Flask(__name__)
app.config.from_pyfile('config.py')

app.register_blueprint(api_bp)

db.init_app(app)
Migrate(app, db)
with app.app_context():
	db.create_all()

ma.init_app(app)
