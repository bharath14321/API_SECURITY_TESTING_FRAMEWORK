"""In-memory data layer for the target API.

Kept deliberately simple (no ORM) so the whole project stays easy to
read end to end. Swap for SQLAlchemy + Postgres if you want to extend
this — the docker-compose.yml has a commented-out Postgres service to
get you started.
"""
from werkzeug.security import generate_password_hash, check_password_hash


class User:
    def __init__(self, id, username, password, is_admin=False, balance=0, email=None):
        self.id = id
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.is_admin = is_admin
        self.balance = balance
        self.email = email or f"{username}@example.com"

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Order:
    def __init__(self, id, user_id, item, amount):
        self.id = id
        self.user_id = user_id
        self.item = item
        self.amount = amount


class InMemoryDB:
    def __init__(self):
        self.users = {}
        self.orders = {}

    def find_user_by_username(self, username):
        for u in self.users.values():
            if u.username == username:
                return u
        return None

    def get_user(self, user_id):
        return self.users.get(user_id)

    def list_users(self):
        return list(self.users.values())

    def save_user(self, user):
        self.users[user.id] = user

    def get_order(self, order_id):
        return self.orders.get(order_id)


db = InMemoryDB()


def init_db():
    """Seed a small, realistic dataset: two regular users and an admin,
    plus an order per regular user. Realistic domain objects (accounts
    with balances, orders) make the vulnerabilities meaningful instead
    of abstract — "user A can read user B's balance" tells a much
    better story than "user A can read user B's todo item"."""
    db.users.clear()
    db.orders.clear()
    db.users[1] = User(1, "alice", "alicepassword", is_admin=False, balance=1000)
    db.users[2] = User(2, "bob", "bobpassword", is_admin=False, balance=2500)
    db.users[3] = User(3, "admin", "adminpassword", is_admin=True, balance=0)

    db.orders[101] = Order(101, user_id=1, item="Laptop", amount=1200)
    db.orders[102] = Order(102, user_id=2, item="Headphones", amount=150)
