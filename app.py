# Python standard libraries
import json
import os
import sqlite3
from uuid import uuid4

# Third-party libraries
from flask import Flask, jsonify, request, redirect, url_for
import requests
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import create_access_token, current_user, jwt_required, JWTManager, get_jwt_identity
from oauthlib.oauth2 import WebApplicationClient

# User imports
from config.google_config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
from auth_utils import get_google_provider_cfg

# Find out what URL to hit for Google login
google_provider_cfg = get_google_provider_cfg()

app = Flask(__name__)


app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///local.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


jwt = JWTManager(app)
db = SQLAlchemy(app)


# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

class User(db.Model):
    id = db.Column(db.Text, default=uuid4().hex, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    full_name = db.Column(db.Text, nullable=True)
    picture = db.Column(db.Text, nullable=True)

    # NOTE: In a real application make sure to properly hash and salt passwords
    def check_password(self, password):
        return safe_str_cmp(password, "password")
    

# Naive database setup
try:
    db.create_all()
    # db.session.add(User(full_name="Bruce Wayne", username="batman"))
    # db.session.add(User(full_name="Ann Takamaki", username="panther"))
    # db.session.add(User(full_name="Jester Lavore", username="little_sapphire"))
    # db.session.commit()
except sqlite3.OperationalError:
    # Assume it's already been created
    pass

# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


# Register a callback function that loades a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


@app.route("/api/login", methods=["POST"])
def api_login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    user = User.query.filter_by(username=username).one_or_none()
    if not user or not user.check_password(password):
        return jsonify("Wrong username or password"), 401

    # Notice that we are passing in the actual sqlalchemy user object here
    access_token = create_access_token(identity=user)
    return jsonify(access_token=access_token)

@app.route("/api/register", methods=["POST"])
def api_register():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    user = User.query.filter_by(username=username).one_or_none()
    if user:
        return jsonify("Account already exists"), 400
    user = User(username=username)
    db.session.add(user)
    db.session.commit()

    # Notice that we are passing in the actual sqlalchemy user object here
    access_token = create_access_token(identity=user)
    return jsonify(access_token=access_token)


@app.route("/api/who_am_i", methods=["GET"])
@jwt_required()
def protected():
    # We can now access our sqlalchemy User object via `current_user`.
    return jsonify(
        id=current_user.id,
        full_name=current_user.full_name,
        username=current_user.username,
    )

@app.route("/")
@jwt_required(optional=True)
def index():
    home_base = '''
        <nav class="menu"> 
            <ul>
                <li><a href="">Home</a></li>
                <li><a href="/me">Me (API)</a></li>
            </ul>
        </nav>
        <h1>Home</h1>'''
    current_identity = get_jwt_identity()
    if current_identity:
        return ( home_base +
            '''
            <p>Hello, {}! You're logged in! Email: {}</p>
            <div><p>Google Profile Picture:</p>
            <img src="{}" alt="Google profile pic"></img></div>
            <a class="button" href="/logout">Logout</a>'''.format(
                current_user.full_name, current_user.username, current_user.id
            )
        )
        # return jsonify(logged_in_as=current_identity)
    else:
        return home_base + '<p>Hello, Anonymous User!</p><a class="button" href="/login">Login</a>'
        # return jsonify(logged_in_as="anonymous user")

@app.route("/login")
def login():
    home_base = '''
        <nav class="menu"> 
            <ul>
                <li><a href="/signup">Signup</a></li>
                <li><a href="/login/google">Google Login</a></li>
            </ul>
        </nav>
        <h1>Login</h1>'''
    return home_base;

@app.route("/login/google")
def google():

    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.host_url + "login/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    token_endpoint = google_provider_cfg["token_endpoint"]
    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
        # Create a user in your db with the information provided
        # by Google
        # Doesn't exist? Add it to the database.
        user = User.query.filter_by(username=users_email).one_or_none()
        if not user:
            user = User(id=unique_id, username=users_email, full_name=users_name, picture=picture)
            db.session.add(user)
            db.session.commit()
            
        access_token = create_access_token(identity=user)
        # print(access_token)
        return jsonify(access_token=access_token)
        # response = redirect(url_for("index"))
        # response.headers={'Authorization': 'Bearer {}'.format(access_token)}
        # return response
    else:
        return jsonify(error="User email not available or not verified by Google."), 400


@app.route("/api/me")
@jwt_required(optional=True)
def profile():
    current_identity = get_jwt_identity()
    if current_identity:
        return jsonify(
            name=current_user.full_name,
            email=current_user.username,
            id=current_user.id,
            picture=current_user.picture)
    else:
        return jsonify(error="unauthorized"), 403


if __name__ == "__main__":
    app.run(ssl_context="adhoc")