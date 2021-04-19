# project/server/__init__.py

import os

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from oauthlib.oauth2 import WebApplicationClient

# User imports
from config.google_config import GOOGLE_CLIENT_ID
app = Flask(__name__)
CORS(app)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY") or "super-secret"  # Change this!
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI") or "sqlite:///local.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.environ.get("SQLALCHEMY_TRACK_MODIFICATIONS") or False


# app_settings = os.getenv(
#     'APP_SETTINGS',
#     'project.server.config.DevelopmentConfig'
# )
# app.config.from_object(app_settings)



jwt = JWTManager(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)
from views.users import auth_blueprint
app.register_blueprint(auth_blueprint)
