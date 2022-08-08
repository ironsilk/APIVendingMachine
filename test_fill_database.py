import sqlalchemy
from models import User

from extensions import db
from main import create_app
from utils import logger


def create_tables(db):
    db.drop_all()
    db.create_all()


def fill_db_test(db):
    from models import User, Product, Role

    user1 = User(username='user1', password='pass1')
    user2 = User(username='user2', password='pass2')
    user3 = User(username='user3', password='pass3')

    user1.products.append(Product(product_name='p1', amount_available=10, cost=5, seller=user1))
    user1.products.append(Product(product_name='p4', amount_available=100, cost=20, seller=user1))
    user3.products.append(Product(product_name='p2', amount_available=10, cost=10, seller=user2))
    user3.products.append(Product(product_name='p3', amount_available=10, cost=15, seller=user3))

    role1 = Role(role_name='buyer')
    role2 = Role(role_name='seller')
    role3 = Role(role_name='admin')

    user1.roles.append(role1)
    user1.roles.append(role2)
    user1.roles.append(role3)

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


app = create_app()
db.init_app(app)
with app.app_context():
    create_tables(db)
    fill_db_test(db)
