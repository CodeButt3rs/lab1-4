import sqlalchemy
import redis
import hashlib
import random
from uuid import UUID
from .models import User, Base, RegisterUser
from ..models.models import AuthUser
from fastapi import exceptions
from sqlalchemy.orm import Session
from sqlalchemy import select


class Postgres:
    def __init__(self):
        self.postgres_engine = sqlalchemy.engine.create_engine("postgresql+psycopg2://postgres:vlald@192.168.1.132:5526/postgres")
        self.session: Session = Session(self.postgres_engine)
        Base.metadata.create_all(bind=self.postgres_engine)

    def register_user(self, user: RegisterUser) -> User:
        users_name = select(User).where(User.user_name == user.user_name)
        users_email = select(User).where(User.user_email == user.email)
        if self.session.scalars(users_name).one_or_none() or self.session.scalars(users_email).one_or_none():
            raise exceptions.HTTPException(status_code=400, detail='User with this username or email already exists')
        created_user: User = User.make_user(user)
        self.session.add(created_user)
        self.session.commit()
        self.session.refresh(created_user)
        return created_user
    
    def get_user_by_id(self, id: UUID) -> User:
        return self.session.scalars(select(User).where(User.id == id)).one_or_none()
    
    def get_user_by_username(self, username: str) -> User:
        return self.session.scalars(select(User).where(User.user_name == username)).one_or_none()
    
    def check_user_auth_info(self, auth_user: AuthUser) -> bool:
        user = self.session.scalars(
            select(User).where(
                User.user_name == auth_user.user_name and User.user_password == User.password_hash(auth_user.user_password)
                )
            ).one_or_none()
        if not user:
            raise exceptions.HTTPException(status_code=401, detail='User login or password is incorrect')
        return user


class Redis:
    def __init__(self):
        self.redis = redis.Redis(host="192.168.1.132", port=5516)

    def get_token(self, user: User, refresh = False) -> str:
        if refresh: self.refresh_token(user)
        return self.redis.get(user.user_hash())

    def refresh_token(self, user: User, minutes: int = 5) -> None:
        self.redis.expire(user.user_hash(), 60 * minutes)

    def remove_token(self, user: User) -> bool:
        return bool(self.redis.delete(user.user_hash()))
    
    def set_token(self, user: User):
        self.redis.set(user.user_hash(), hashlib.sha256(f'{str(random.randrange(10000, 100000000000000))}{user.id}'.encode(encoding='utf-8')).hexdigest())
        return self.get_token(user)

    def verify_token(self, user: User, token: str) -> bool:
        return str(self.redis.get(user.user_hash())).replace("'", "")[1:] == token


class DatabaseManager:
    def __init__(self):
        self.postgresql = Postgres()
        self.redis = Redis()
        self.connect()

    def register_user(self, user: RegisterUser) -> User:
        return self.postgresql.register_user(user)
    
    def auth_user_by_log_pass(self, user: AuthUser) -> str:
        user = self.postgresql.check_user_auth_info(user) 
        return self.redis.set_token(user)
    
    def get_user(self, username: str) -> User:
        return self.postgresql.get_user_by_username(username)

    def set_redis(self, redis: Redis):
        self.redis = redis

    def set_postgres(self, postgresql: Postgres):
        self.postgresql = postgresql

    def connect(self):
        self.postgresql.postgres_engine.connect()
        self.redis.redis.client()
    
    def verify_token(self, username: str, token: str) -> bool:
        user = self.postgresql.get_user_by_username(username)
        if not user:
            return False
        return self.redis.verify_token(user, token)

    def insert_token(self, user: User) -> bool:
        self.redis.set_token(user)

    def delete_token(self, user: User) -> bool:
        return self.redis.remove_token(user)

    def insert_user(self) -> User:
        User.user_name

database_mgr = DatabaseManager()