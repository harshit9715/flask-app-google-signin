from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from flask_jwt_extended import create_access_token, current_user, jwt_required, get_jwt
from datetime import datetime, timezone
import requests
from app import bcrypt, db, jwt, client
from db.Models import User, BlacklistToken
from auth_utils import get_google_provider_cfg
import sqlite3
import json


# User imports
from config.google_config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET

auth_blueprint = Blueprint('auth', __name__)

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

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.query(BlacklistToken.id).filter_by(jti=jti).scalar()
    return token is not None

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # get the post data
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(username=post_data.get('username')).first()
        if not user:
            try:
                user = User(
                    username=post_data.get('username'),
                    password=post_data.get('password')
                )
                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                auth_token = create_access_token(identity=user)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202


class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            user = User.query.filter_by(
                username=post_data.get('username')
            ).first()
            if user and bcrypt.check_password_hash(
                user.hash, post_data.get('password')
            ):
                auth_token = create_access_token(identity=user)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


class FederatedLoginAPI(MethodView):
    """
    Federated Login Resource
    """
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    def get(self):

        authorization_endpoint = self.google_provider_cfg["authorization_endpoint"]

        # Use library to construct the request for Google login and provide
        # scopes that let you retrieve user's profile from Google
        request_uri = client.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=request.host_url + "login/callback",
            scope=["openid", "email", "profile"],
        )
        return jsonify(google=request_uri, usage='call from browser')

    def post(self):

        # get the post data
        post_data = request.get_json()
        # Get authorization code Google sent back to you
        # code = post_data.get("code")
        url = post_data.get("url")

        # Find out what URL to hit to get tokens that allow you to ask for
        # things on behalf of a user
        token_endpoint = self.google_provider_cfg["token_endpoint"]
        # Prepare and send a request to get tokens! Yay tokens!
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=url,
            redirect_url=request.host_url + "login/callback",
            # code=code
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
        userinfo_endpoint = self.google_provider_cfg["userinfo_endpoint"]
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



class UserAPI(MethodView):
    """
    User Resource
    """
    @jwt_required()
    def get(self):
        user = User.query.filter_by(id=current_user.id).first()
        responseObject = {
            'status': 'success',
            'data': user.to_json()
        }
        return make_response(jsonify(responseObject)), 200


class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        now = datetime.now(timezone.utc)
        db.session.add(BlacklistToken(jti=jti, created_at=now))
        db.session.commit()
        return jsonify(msg="JWT revoked")

# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')
federated_login_view = FederatedLoginAPI.as_view('federated_login_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/auth/google',
    view_func=federated_login_view,
    methods=['GET', 'POST']
)