import jwt
from flask import json
from flask_bcrypt import generate_password_hash
from jwt import ExpiredSignatureError
from sqlalchemy.ext.declarative import DeclarativeMeta
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from werkzeug.security import generate_password_hash

from extensions import db

# Relationship table between users and roles
user_roles = db.Table('user_roles',
                      db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                      db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
                      )


class AlchemyEncoder(json.JSONEncoder):
    """
    JSON encoder
    """

    def default(self, o):
        if isinstance(o.__class__, DeclarativeMeta):
            data = {}
            fields = o.__json__() if hasattr(o, '__json__') else dir(o)
            for field in [f for f in fields if not f.startswith('_') and f not in ['metadata', 'query', 'query_class']]:
                value = o.__getattribute__(field)
                try:
                    json.dumps(value)
                    data[field] = value
                except TypeError:
                    data[field] = None
            return data
        return json.JSONEncoder.default(self, o)


class User(db.Model, SerializerMixin):
    serialize_rules = ('-products.user',)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    _password = db.Column(db.String(128))
    deposit = db.Column(db.Integer, default=0)

    roles = db.relationship('Role', secondary=user_roles)
    products = db.relationship("Product")

    def __repr__(self):
        return '<User %r>' % self.username

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, plaintext):
        self._password = generate_password_hash(plaintext)


class Product(db.Model, SerializerMixin):
    serialize_rules = ('-products.user',)

    id = db.Column(db.Integer, primary_key=True)
    amount_available = db.Column(db.Integer)
    cost = db.Column(db.Integer, db.CheckConstraint("cost%5=0"))
    product_name = db.Column(db.String(100))

    seller = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Product %r>' % self.product_name


class Role(db.Model, SerializerMixin):
    serialize_rules = ('-roles.user',)

    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(100))

    def __repr__(self):
        return '<Role %r>' % self.role_name


class LoggedInUser(db.Model, SerializerMixin):

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    token = db.Column(db.String(256))
    token_status = db.Column(db.String(64))


def clean_invalid_tokens(user, secret_key):
    valid_tokens = []
    other_sessions = LoggedInUser.query.filter_by(
        user_id=user.id,
        token_status='valid'
    ).all()
    for session in other_sessions:
        try:
            jwt.decode(
            jwt=session.token,
            key=secret_key,
            algorithms='HS256'
        )
        except ExpiredSignatureError:
            session.token_status = 'expired'  # this way we also keep login history, can be simply deleted otherwise
            db.session.add(session)
            continue
        valid_tokens.append(session)
        db.session.commit()
    return valid_tokens


def expire_all_user_tokens(user):
    db.session.query(LoggedInUser).filter_by(user_id=user.id).update({'token_status': 'expired'})
    db.session.commit()


def token_manually_expired(user_id, token):
    return LoggedInUser.query.filter_by(
        user_id=user_id,
        token=token,
        token_status='expired'
    ).first()


def get_role(role_name):
    return Role.query.filter(Role.role_name == role_name).first()


def get_user(username):
    return User.query.filter(User.username == username).first()
