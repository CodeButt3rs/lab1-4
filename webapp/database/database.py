import sqlalchemy
import redis
import hashlib
import random
from uuid import UUID

import sqlalchemy.orm
from .models import User, Base, RegisterUser, Role, Permissions
from ..models.models import AuthUser, RequestRole, UpdateRole, RequestPermission, UpdatePermission
from fastapi import exceptions
from sqlalchemy.orm import Session
from sqlalchemy import select


class Postgres:
    def __init__(self):
        self.postgres_engine = sqlalchemy.engine.create_engine("postgresql+psycopg2://postgres:vlald@192.168.1.132:5526/development")
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

    def get_all_users(self) -> list[User]:
        return self.session.scalars(select(User)).all() 

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
    
    def get_roles(self) -> list[Role]:
        return self.session.scalars(select(Role).where(Role.role_deleted_at.is_(None))).all()
    
    def get_role(self, id: UUID) -> Role:
        return self.session.scalars(select(Role).where(Role.id == id).where(Role.role_deleted_at.is_(None))).one_or_none()
    
    def create_role(self, role: RequestRole, user: User) -> Role:
        role_code = select(Role).where(Role.role_code == role.role_code)
        if self.session.scalars(role_code).one_or_none():
            raise exceptions.HTTPException(status_code=400, detail='Role with this code already exists')
        created_role: Role = Role.make_role(role, user)
        self.session.add(created_role)
        self.session.commit()
        self.session.refresh(created_role)
        return created_role

    def update_role(self, id: UUID, updated_role: UpdateRole) -> Role:
        role = self.session.scalars(select(Role).where(Role.id == updated_role.role_id).where(Role.role_deleted_at.is_(None))).one_or_none()
        if not role:
            raise exceptions.HTTPException(status_code=400, detail='Role with this ID does not exist')
        if self.session.scalars(select(Role).where(Role.role_code == updated_role.role_code)).one_or_none():
            raise exceptions.HTTPException(status_code=400, detail='Role with that code already exists')
        role.apply_changes(updated_role)
        self.session.commit()
        self.session.refresh(role)
        return role
    
    def delete_role_soft(self, id: UUID, user: User) -> Role:
        role = self.session.scalars(select(Role).where(Role.id == id).where(Role.role_deleted_at.is_(None))).one_or_none()
        if not role:
            raise exceptions.HTTPException(status_code=400, detail='Role with this ID does not exist')
        role.soft_delete(user)
        self.session.commit()
        self.session.refresh(role)
        return role
    
    def delete_role_hard(self, id: UUID) -> bool:
        role = self.session.scalars(select(Role).where(Role.id == id)).one_or_none()
        if not role:
            raise exceptions.HTTPException(status_code=400, detail='Role with this ID does not exist')
        self.session.delete(role)
        self.session.commit()
        return True
    
    def restore_role_soft(self, id: UUID) -> Role:
        role = self.session.scalars(select(Role).where(Role.id == id).where(Role.role_deleted_at.is_not(None))).one_or_none()
        if not role:
            raise exceptions.HTTPException(status_code=400, detail='Role with this ID does not exist or role not deleted')
        role.restore_soft()
        self.session.commit()
        self.session.refresh(role)
        return role
    
    def set_user_role(self, user_id: UUID, role_id: UUID) -> User:
        role = self.session.scalars(select(Role).where(Role.id == role_id).where(Role.role_deleted_at.is_(None))).one_or_none()
        user = self.session.scalars(select(User).where(User.id == user_id)).one_or_none()
        if not (role and user):
            raise exceptions.HTTPException(status_code=400, detail='Role or user with this ID does not exist')
        user.set_role(role)
        self.session.commit()
        self.session.refresh(user)
        return user
    
    def get_premissions(self) -> list[Permissions]:
        return self.session.scalars(select(Permissions).where(Permissions.permission_deleted_at.is_(None))).all()
    
    def get_premission(self, id: UUID) -> Permissions:
        return self.session.scalars(select(Permissions).where(Permissions.id == id)).one_or_none()
    
    def get_premission_by_code(self, code: str) -> Permissions:
        return self.session.scalars(select(Permissions).where(Permissions.permission_code == code)).one_or_none()
    
    def create_premission(self, permission: RequestPermission, user: User) -> Permissions:
        permission_code = select(Permissions).where(Permissions.permission_code == permission.permission_code).where(Permissions.permission_deleted_at.is_(None))
        if self.session.scalars(permission_code).one_or_none():
            raise exceptions.HTTPException(status_code=400, detail='permission with this code already exists')
        created_permission: Permissions = Permissions.make_permission(permission, user)
        self.session.add(created_permission)
        self.session.commit()
        self.session.refresh(created_permission)
        return created_permission

    def update_premission(self, id: UUID, updated_permission: UpdatePermission) -> Permissions:
        role = self.session.scalars(select(Permissions).where(Permissions.id == updated_permission.permission_id).where(Permissions.permission_deleted_at.is_(None))).one_or_none()
        if not role:
            raise exceptions.HTTPException(status_code=400, detail='permission with this ID does not exist')
        if self.session.scalars(select(Permissions).where(Permissions.permission_code == updated_permission.permission_code).where(Permissions.permission_deleted_at.is_(None))).one_or_none():
            raise exceptions.HTTPException(status_code=400, detail='permission with that code already exists')
        role.apply_changes(updated_permission)
        self.session.commit()
        self.session.refresh(role)
        return role
    
    def delete_premission_soft(self, id: UUID, user: User) -> Permissions:
        permission = self.session.scalars(select(Permissions).where(Permissions.id == id).where(Permissions.permission_deleted_at.is_(None))).one_or_none()
        if not permission:
            raise exceptions.HTTPException(status_code=400, detail='permission with this ID does not exist')
        permission.soft_delete(user)
        self.session.commit()
        self.session.refresh(permission)
        return permission
    
    def delete_premission_hard(self, id: UUID) -> bool:
        permission = self.session.scalars(select(Permissions).where(Permissions.id == id)).one_or_none()
        if not permission:
            raise exceptions.HTTPException(status_code=400, detail='permission with this ID does not exist')
        self.session.delete(permission)
        self.session.commit()
        return True
    
    def restore_premission_soft(self, id: UUID) -> Permissions:
        permission = self.session.scalars(select(Permissions).where(Permissions.id == id).where(Permissions.permission_deleted_at.is_not(None))).one_or_none()
        if not permission:
            raise exceptions.HTTPException(status_code=400, detail='permission with this ID does not exist or permission not deleted')
        permission.restore_soft()
        self.session.commit()
        self.session.refresh(permission)
        return permission
    
    def set_permission_to_role(self, role_id: UUID, permission_id: UUID) -> Role:
        role = self.session.scalars(select(Role).where(Role.id == role_id).where(Role.role_deleted_at.is_(None))).one_or_none()
        permission = self.session.scalars(select(Permissions).where(Permissions.id == permission_id).where(Permissions.permission_deleted_at.is_(None))).one_or_none()
        if not role and permission:
            raise exceptions.HTTPException(status_code=400, detail='Role or permission with this ID does not exist')
        role.add_permission(permission)
        self.session.commit()
        self.session.refresh(role)
        return role
        

class Redis:
    def __init__(self):
        self.redis = redis.Redis(host="192.168.1.132", port=5516)

    def get_token(self, user: User, refresh = False) -> str:
        if refresh: self.refresh_token(user)
        return str(self.redis.get(user.user_hash()))

    def refresh_token(self, user: User, minutes: int = 5) -> None:
        self.redis.expire(user.user_hash(), 60 * minutes)

    def remove_token(self, user: User) -> bool:
        return bool(self.redis.delete(user.user_hash()))
    
    def set_token(self, user: User):
        self.redis.set(user.user_hash(), hashlib.sha256(f'{str(random.randrange(10000, 100000000000000))}{user.id}'.encode(encoding='utf-8')).hexdigest(), ex= 5 * 60)
        return self.get_token(user, True)

    def verify_token(self, user: User, token: str) -> bool:
        # .replace("'", "")[1:]
        return str(self.get_token(user, refresh=True)[2:-1]) == token


class DatabaseManager:
    def __init__(self):
        self.postgresql = Postgres()
        self.redis = Redis()
        self.connect()

    # AUTH SECTION
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

    # ROLE SECTION
    def get_all_roles(self) -> list[Role]:
        return self.postgresql.get_roles()

    def get_role_by_id(self, id: str) -> list[Role]:
        return self.postgresql.get_role(id)
    
    def create_role(self, role: RequestRole, user_name: str) -> Role:
        return self.postgresql.create_role(role, self.postgresql.get_user_by_username(user_name))
    
    def update_role(self, id: UUID, role: UpdateRole) -> Role:
        return self.postgresql.update_role(id, role)
    
    def delete_role_hard(self, id: UUID, role: RequestRole) -> Role:
        return self.postgresql.delete_role_hard(id)
    
    def delete_role_soft(self, id: UUID, user_name: str) -> Role:
        return self.postgresql.delete_role_soft(id, self.postgresql.get_user_by_username(user_name))
    
    def restore_role_soft(self, id: UUID) -> Role:
        return self.postgresql.restore_role_soft(id)
    
    def add_permission_role(self, role_id: str, permission_id) -> Role:
        return self.postgresql.set_permission_to_role(role_id, permission_id)
    
    # PERMISSIONS SECTION
    def get_all_permissions(self) -> list[Role]:
        return self.postgresql.get_premissions()

    def get_permission_by_id(self, id: str) -> list[Role]:
        return self.postgresql.get_premission(id)
    
    def create_permission(self, role: RequestPermission, user_name: str) -> Role:
        return self.postgresql.create_premission(role, self.postgresql.get_user_by_username(user_name))
    
    def update_permission(self, id: UUID, role: UpdatePermission) -> Role:
        return self.postgresql.update_premission(id, role)
    
    def delete_permission_hard(self, id: UUID) -> Role:
        return self.postgresql.delete_premission_hard(id)
    
    def delete_permission_soft(self, id: UUID, user_name: str) -> Role:
        return self.postgresql.delete_premission_soft(id, self.postgresql.get_user_by_username(user_name))
    
    def restore_permission_soft(self, id: UUID) -> Role:
        return self.postgresql.restore_premission_soft(id)
    
    def check_user_access(self, user_id: UUID, permission_code: str) -> bool:
        user = self.postgresql.get_user_by_username(user_id).user_role
        permission = self.postgresql.get_premission_by_code(permission_code)
        return permission in self.postgresql.get_role(user)._permissions
    
    # USER SECTION
    def get_users_list(self):
        return self.postgresql.get_all_users()
    
    def set_user_role(self, user_id: UUID, role_id: UUID):
        return self.postgresql.set_user_role(user_id, role_id)
    
    def reset_user_role(self, user_id: UUID):
        default_role = self.postgresql.session.scalars(select(Role).where(Role.role_code == 'DEFAULT_GUEST')).one_or_none()
        return self.postgresql.set_user_role(user_id, default_role.id)

database_mgr = DatabaseManager()