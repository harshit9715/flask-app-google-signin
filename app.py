# project/server/__init__.py

import os

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
app = Flask(__name__)
CORS(app)

app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///local.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# app_settings = os.getenv(
#     'APP_SETTINGS',
#     'project.server.config.DevelopmentConfig'
# )
# app.config.from_object(app_settings)



jwt = JWTManager(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

from views.users import auth_blueprint
app.register_blueprint(auth_blueprint)