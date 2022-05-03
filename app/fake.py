from random import randint
from sqlalchemy.exc import IntegrityError
from faker import Faker
from mdgen import MarkdownPostProvider
from . import db
from .models import Post, User

def users(count=100):
    fake = Faker()
    i = 0
    while i < count:
        u = User(email=fake.email(),
        username=fake.user_name(),
        password='password',
        confirmed=True,
        name=fake.name(),
        location=fake.city(),
        about_me=fake.text(),
        member_since=fake.past_date())
        db.session.add(u)
        try:
            db.session.commit()
            i += 1
        except IntegrityError:
            db.session.rollback()

def posts(count=100):
    fake = Faker()
    fake.add_provider(MarkdownPostProvider)
    user_count = User.query.count()
    for i in range(count):
        u = User.query.offset(randint(0, user_count - 1)).first()
        p = Post(body=fake.post(size='medium'),
        timestamp=fake.past_date(),
        author=u)
        db.session.add(p)
    db.session.commit()

def follows(count=100):
    user_count = User.query.count()
    i = 0 
    while i < count:
        u1 = User.query.offset(randint(0, user_count - 1)).first()
        u2 = User.query.offset(randint(0, user_count - 1)).first()
        if u1 != u2:
            u1.follow(u2)
            try:
                db.session.commit()
                i += 1
            except IntegrityError:
                db.session.rollback()