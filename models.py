# creates SQLALCHEMY object
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import generate_password_hash
from werkzeug.security import generate_password_hash
from sqlalchemy.ext.hybrid import hybrid_property

from main import app

db = SQLAlchemy(app)


user_roles = db.Table('user_roles',
                      db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                      db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
                      )


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    _password = db.Column(db.String(128))
    deposit = db.Column(db.Integer)

    roles = db.relationship('Role', secondary=user_roles,
                            backref='role')
    products = db.relationship("Product", backref='product')

    def __repr__(self):
        return '<User %r>' % self.username

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, plaintext):
        self._password = generate_password_hash(plaintext)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amountAvailable = db.Column(db.Integer)
    cost = db.Column(db.Integer, db.CheckConstraint("cost%5=0"))
    productName = db.Column(db.String(100))

    sellerID = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<User %r>' % self.productName


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    roleName = db.Column(db.String(100))

    def __repr__(self):
        return '<User %r>' % self.roleName

