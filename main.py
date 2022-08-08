import os
from copy import copy
from datetime import datetime, timedelta
from functools import wraps

import jwt
from dotenv import load_dotenv
from flask import Flask, jsonify, request, abort, make_response
from werkzeug.security import check_password_hash

from extensions import db
from models import User, AlchemyEncoder, Role, Product, LoggedInUser, clean_invalid_tokens, expire_all_user_tokens, \
    token_manually_expired
from utils import calculate_change

load_dotenv()

# ENV variables
POSTGRES_DB = os.getenv('POSTGRES_DB')
POSTGRES_HOST = os.getenv('POSTGRES_HOST')
POSTGRES_PORT = os.getenv('POSTGRES_PORT')
POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')


def register_extensions(app):
    db.init_app(app)


def create_app():
    app = Flask(__name__)
    app.json_encoder = AlchemyEncoder

    app.config['SECRET_KEY'] = 'big secret'
    # database name
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

    register_extensions(app)

    return app


app = create_app()


def token_required(f):
    """
    JWT token-based auth wrapper
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'Authorization' in request.headers:
            token = request.headers.get('Authorization')
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # Check if token is valid
            token = token.replace("Bearer ", '')
            data = jwt.decode(
                jwt=token,
                key=app.config['SECRET_KEY'],
                algorithms=['HS256']
            )
            # Check if token hasn't been manually expired
            if token_manually_expired(data['id'], token):
                return jsonify({'message': 'You have been logged out!'}), 401

            current_user = User.query \
                .filter_by(id=data['id']) \
                .first()
        except Exception as e:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)

    return decorated


def user_has_permission(f):
    """
    Wrapper to determine if user can access or edit
    certain resources.
    """

    @wraps(f)
    def decorated(current_user, id, *args, **kwargs):
        if current_user.id == int(id) or 'admin' in [x.role_name for x in current_user.roles]:
            return f(current_user, id, *args, **kwargs)
        return abort(403, "You don't have the necessary permission to access this data")

    return decorated


def user_is_seller(f):
    """
    Wrapper to determine if the user is a seller
    """

    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        user_roles = [x.role_name for x in current_user.roles]
        if 'seller' in user_roles or \
                'admin' in user_roles:
            return f(current_user, *args, **kwargs)
        return abort(403, "You don't have the necessary permission to access this data")

    return decorated


def user_is_buyer(f):
    """
    Wrapper to determine if the user is a buyer
    """

    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        user_roles = [x.role_name for x in current_user.roles]
        if 'buyer' in user_roles or \
                'admin' in user_roles:
            return f(current_user, *args, **kwargs)
        return abort(403, "You don't have the necessary permission to access this endpoint")

    return decorated


@app.route('/login', methods=['POST'])
def login():
    """
    Route for logging in and obtaining the JWT token
    """

    if not request.json:
        abort(400)
    auth = request.json
    if not auth.get('username') or not auth.get('password'):
        # returns 401 if any username or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required"'}
        )

    user = User.query \
        .filter_by(username=auth.get('username')) \
        .first_or_404()

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        pkg = {
            'token': jwt.encode({
                'id': user.id,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, app.config['SECRET_KEY'])
        }

        # First clean database of invalid tokens
        valid_sessions = clean_invalid_tokens(user, app.config['SECRET_KEY'])

        # Prompt user if there is someone else logged in with these credentials:

        if valid_sessions:
            pkg['warning'] = f"User already logged in {len(valid_sessions)} other sessions, " \
                             f"use /logout/all to exit all sessions."

        # Add current jwt token to database
        new_login = LoggedInUser(
            user_id=user.id,
            token=pkg['token'],
            token_status='valid',
        )
        db.session.add(new_login)
        db.session.commit()

        return make_response(jsonify(pkg), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password"'}
    )


@app.route('/logout/all', methods=["GET"])
@token_required
def logout(current_user):
    # Expires all tokens.
    expire_all_user_tokens(current_user)
    return jsonify({'result': True})


@app.route('/user/', methods=['POST'])
def create_user():
    """
    Route to create a user, public access.
    """

    if not request.json:
        abort(400)
    # Username conflict (it should be treated in frontEnd)
    if User.query.filter_by(username=request.json.get('username')).first():
        abort(409, 'Username already exists, please pick another username')

    # Password requirements, simple example (it should be treated in frontEnd)
    if len(request.json.get('password')) < 4:
        abort(422, 'Password does not meet minimum requirements')

    new_user = User(username=request.json.get('username'),
                    password=request.json.get('password'),
                    deposit=request.json.get('deposit')
                    )
    for role_name in request.json.get('roles'):
        new_user.roles.append(Role.query.filter_by(role_name=role_name).first())
    db.session.add(new_user)
    db.session.commit()
    return jsonify(new_user.to_dict(rules=('-_password',)))


# USER API ENDPOINTS

@app.route('/user/<id>', methods=["GET"])
@token_required
@user_has_permission
def get_user(current_user, id):
    """
    Route to get user data, will be restricted as such:
    1. Logged in users can acccess their data.
    2. Admins can access other users's data.
    """
    user = User.query.filter_by(id=id).first_or_404()
    return user.to_dict(rules=('-_password',))


@app.route("/user/<id>", methods=["DELETE"])
@token_required
@user_has_permission
def delete_user(current_user, id):
    """
    Route to delete user data, will be restricted as such:
    1. Logged in users can delete their account.
    2. Admins can access other users's data.
    """
    user = User.query.filter_by(id=id).first_or_404()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'result': True})


@app.route("/user/<id>", methods=["PUT"])
@token_required
@user_has_permission
def update_user(current_user, id):
    """
    Route to update user data, will be restricted as such:
    1. Logged in users can delete their account.
    2. Admins can access other users's data.
    """

    if not request.json:
        abort(400)
    user = User.query.filter_by(id=id).first_or_404()
    if request.json.get('username'):
        user.username = request.json.get('username')
    if request.json.get('password'):
        user.password = request.json.get('password')
    if request.json.get('deposit'):
        user.deposit = request.json.get('deposit')
    # Here it can probably implemented in a number of ways,
    # we're assuming that on update there will be mentioned all
    # the new roles of the user.
    if request.json.get('roles'):
        user.roles = []
        for role_name in request.json.get('roles'):
            user.roles.append(Role.query.filter_by(role_name=role_name).first())
    db.session.add(user)
    db.session.commit()
    return jsonify({'result': True})


# PRODUCTS API ENDPOINTS

@app.route('/product/', methods=['POST'])
@token_required
@user_is_seller
def create_product(current_user):
    """
    Route to create a product.
    Only authenticated users with seller role
    """

    if not request.json:
        abort(400)

    new_product = Product(amount_available=request.json.get('amount_available'),
                          cost=request.json.get('cost'),
                          product_name=request.json.get('product_name'),
                          seller=current_user.id,
                          )
    db.session.add(new_product)
    db.session.commit()
    return jsonify(new_product.to_dict())


@app.route("/product/<id>", methods=["DELETE"])
@token_required
@user_is_seller
def delete_product(current_user, id):
    """
    Route to delete product, will be restricted as such:
    1. Logged in sellers.
    2. Admins can access other users's data.
    """
    product = Product.query.filter_by(id=id).first_or_404()
    if product.seller == current_user.id or 'admin' in [x.role_name for x in current_user.roles]:
        db.session.delete(product)
        db.session.commit()
        return jsonify({'result': True})
    else:
        abort(403, "Not your product, bro.")


@app.route("/product/<id>", methods=["PUT"])
@token_required
@user_is_seller
def update_product(current_user, id):
    """
    Route to update product, will be restricted as such:
    1. Logged in sellers.
    2. Admins can access other users's data.
    """

    if not request.json:
        abort(400)

    product = Product.query.filter_by(id=id).first_or_404()
    if product.seller == current_user.id or 'admin' in [x.role_name for x in current_user.roles]:
        if request.json.get('amount_available'):
            product.amount_available = request.json.get('amount_available')
        if request.json.get('cost'):
            product.cost = request.json.get('cost')
        if request.json.get('product_name'):
            product.product_name = request.json.get('product_name')
        db.session.add(product)
        db.session.commit()
        return jsonify({'result': True})
    else:
        abort(403, "Not your product, bro.")


@app.route('/product/<id>', methods=["GET"])
@token_required
def get_product(current_user, id):
    """
    Route to get product info, will be restricted as such:
    1. Logged in users.
    """
    product = Product.query.filter_by(id=id).first_or_404()
    return product.to_dict()


@app.route('/deposit/', methods=["POST"])
@token_required
@user_is_buyer
def deposit(current_user):
    """
    Route to deposit, will be restricted as such:
    1. Logged in buyers.
    """
    if not request.json:
        abort(400)
    amount = request.json.get('amount')
    if not amount or amount not in [5, 10, 20, 50, 100]:
        abort(409, "Please provide a request with an `amount` key. Value must"
                   "be 5,10,20,50 or 100.")
    current_user.deposit += amount
    db.session.add(current_user)
    db.session.commit()
    return jsonify({'result': f"Inserted {amount} into wallet."})


@app.route('/buy/', methods=["POST"])
@token_required
@user_is_buyer
def buy(current_user):
    """
    Route to buy products. Rules:
    1. Logged in buyers.
    2. Can buy only one product at a time,
    3. Returns total spent, product purchased and change
    4. JSON arguments needed: product_id, amount
    """

    if not request.json:
        abort(400)
    product_id = request.json.get('product_id')
    amount = request.json.get('amount')
    if not amount or not product_id:
        abort(409, "Please provide a request with an `amount` key.")

    product = Product.query.filter_by(id=product_id).first_or_404()
    necessary_funds = product.cost * int(amount)

    # Check if user has necessary funds
    if not current_user.deposit >= necessary_funds:
        abort(409, f"Not enough cash. Your deposit stands at {current_user.deposit}"
                   f" while necessary_funds stands at {necessary_funds}")

    # Check if there are enough products
    if not product.amount_available >= int(amount):
        abort(409, f"Insufficient product amount, maximum available: {product.amount_available}")

    change = current_user.deposit - necessary_funds
    current_user.deposit = 0
    product.amount_available -= int(amount)
    db.session.add(current_user)
    db.session.add(product)
    db.session.commit()
    return jsonify({
        'result': "Transaction complete",
        'total_spent': necessary_funds,
        'product': product.product_name,
        'change': calculate_change(change),
    })


@app.route('/reset/', methods=["GET"])
@token_required
@user_is_buyer
def reset(current_user):
    """
    Route to reset deposit, should return change.
    1. Logged in buyers can access
    """

    change = copy(current_user.deposit)
    if change != 0:
        current_user.deposit = 0
        db.session.add(current_user)
        db.session.commit()
    return jsonify({
        'result': "Reset complete, here's your change",
        'change': calculate_change(change),
    })


if __name__ == '__main__':
    db.init_app(app)
    app.run(host='0.0.0.0', port=4231)
