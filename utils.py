# decorator for verifying the JWT
import logging
from functools import wraps
import jwt
import sqlalchemy.exc
from flask import jsonify
from models import User
from main import app


# Logger settings
def setup_logger(name, log_file=None, level=logging.INFO):
    """Function to setup as many loggers as you want"""
    formatter = logging.Formatter('[%(asctime)s] {%(filename)s:%(lineno)d} [%(name)s] [%(levelname)s] --> %(message)s')
    out_handler = logging.StreamHandler()
    out_handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(out_handler)
    if log_file:
        handler = logging.FileHandler(log_file, encoding='utf8')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


logger = setup_logger("APIVendingMachine")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query \
                .filter_by(public_id=data['public_id']) \
                .first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)

    return decorated


def create_tables():
    from models import db
    db.drop_all()
    db.create_all()


def fill_db_test():
    from models import db, User, Product, Role

    user1 = User(username='The First', password='pass1')
    user2 = User(username='The Second', password='pass2')
    user3 = User(username='The Third', password='pass3')

    user1.products.append(Product(productName='p1', amountAvailable=10, cost=5, sellerID=user1))
    user1.products.append(Product(productName='p4', amountAvailable=100, cost=20, sellerID=user1))
    user2.products.append(Product(productName='p2', amountAvailable=10, cost=10, sellerID=user2))
    user3.products.append(Product(productName='p3', amountAvailable=10, cost=15, sellerID=user3))

    role1 = Role(id=1, roleName='buyer')
    role2 = Role(id=2, roleName='seller')

    user1.roles.append(role1)
    user1.roles.append(role2)
    user2.roles.append(role1)
    user3.roles.append(role2)

    db.session.add_all([user1, user2, user3])

    db.session.commit()


def test_cost_constraint():
    """
    Check if the cost of the product can only be entered in multiples
    of 5. Will throw an IntegrityError.
    """

    from models import db, Product

    user = db.session.query(User).all()[0]

    user.products.append(Product(productName='p1', amountAvailable=10, cost=6, sellerID=user))
    db.session.add_all([user])
    try:
        db.session.commit()
    except sqlalchemy.exc.IntegrityError:
        logger.info("Test passed, cost can only be multiples of 5.")


if __name__ == '__main__':
    create_tables()
    fill_db_test()
    test_cost_constraint()
