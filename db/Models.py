from uuid import uuid4
from datetime import datetime
from app import app, db, bcrypt

class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "users"

    id = db.Column(db.Text, default=uuid4().hex, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    full_name = db.Column(db.Text, nullable=True)
    registered_on = db.Column(db.DateTime, nullable=False)
    picture = db.Column(db.Text, nullable=True)
    role = db.Column(db.Text, nullable=False, default='viewer')
    hash = db.Column(db.Text, nullable=True)


    def __init__(self, username, password=None, id=uuid4().hex,role='viewer', full_name=None, picture=None):
        self.id = id
        self.username = username
        self.hash = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode() if password else None
        self.registered_on = datetime.now()
        self.role = role
        self.full_name = full_name
        self.picture = picture
    
    # NOTE: In a real application make sure to properly hash and salt passwords
    def check_password(self, password):
        return bcrypt.check_password_hash(self.hash, password)
    
    def to_json(self):
        return {"id":self.id, "username":self.username, "name": self.full_name, "picture": self.picture}


class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

