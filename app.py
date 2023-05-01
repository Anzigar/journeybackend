from flask import Flask
from flask_migrate import Migrate
from models import db
from item import ma
from routes import api_bp
from flask_jwt_extended import JWTManager
from flask_login import LoginManager

# initialize app
app = Flask(__name__)
app.config.from_pyfile('config.py')
app.config['SECRET_KEY'] = 'your-secret-key'  # set a secret key for the app
app.config['JWT_SECRET_KEY'] = ''
UPLOAD_FOLDER = '/path/to/upload/folder'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
jwt = JWTManager(app)
app.register_blueprint(api_bp)
login_manager = LoginManager()
login_manager.init_app(app)
db.init_app(app)
Migrate(app, db)
with app.app_context():
	db.create_all()

ma.init_app(app)
