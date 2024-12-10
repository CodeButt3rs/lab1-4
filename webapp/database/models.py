from __future__ import annotations
import sqlalchemy.event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, registry, Session, scoped_session, sessionmaker
from sqlalchemy.dialects.postgresql import UUID
from redis_om import HashModel
from uuid import UUID, uuid4
from datetime import date
from ..models.models import RegisterUser, RequestRole, UpdateRole, RequestPermission, UpdatePermission
from typing import List
from datetime import datetime
from sqlalchemy import text, select, Column, ForeignKey, String, Date, DateTime, Connection, UUID
import sqlalchemy
import hashlib


class Base(DeclarativeBase):
    pass


middle_table_roles_permissions = sqlalchemy.Table(
    "roles_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("user_role.id")),
    Column("permission_id", ForeignKey("role_permission.id"))
)

class User(Base):
    __tablename__ = "user_account"

    id: Mapped[UUID] = mapped_column(UUID, unique=True, primary_key=True, default=uuid4)
    user_name: Mapped[str] = mapped_column(String, unique=True)
    user_password: Mapped[str] = mapped_column(String(256))
    user_email: Mapped[str] = mapped_column(String(256), unique=True)
    user_birthday: Mapped[date] = mapped_column(Date)
    user_role: Mapped["_role"] = mapped_column(
        ForeignKey("user_role.id"), 
        nullable=True, 
        default=select(text("id from user_role")).where(text("role_code = 'USER_DEFAULT'"))
        )

    _role: Mapped["Role"] = relationship("Role", foreign_keys=[user_role])

    def user_hash(self):
        return hashlib.sha256(str(self.id).encode(encoding='utf-8', errors = 'strict')).hexdigest()
    
    def password_hash(password_str: str):
        return hashlib.sha256(password_str.encode(encoding = 'UTF-8', errors = 'strict')).hexdigest()
    
    def make_user(user: RegisterUser):
        return User(
            user_name=user.user_name, 
            user_password=User.password_hash(user.user_password),
            user_email=user.email,
            user_birthday=user.birthday
            )
    
    def set_role(self, role: Role):
        self._role = role


class Role(Base):
    __tablename__ = "user_role"

    id: Mapped[UUID] = mapped_column(UUID, unique=True, primary_key=True, default=uuid4)
    role_name: Mapped[str] = mapped_column(String, unique=True)
    role_description: Mapped[str] = mapped_column(String)
    role_code: Mapped[str] = mapped_column(String(256), unique=True)
    role_created_at: Mapped[date] = mapped_column(DateTime, default=datetime.now)
    role_created_by: Mapped["User"] = mapped_column(ForeignKey("user_account.id"), nullable=True, default=None)
    role_deleted_at: Mapped[date] = mapped_column(Date, nullable=True, default=None)
    role_deleted_by: Mapped["User"] = mapped_column(ForeignKey("user_account.id"), nullable=True, default=None)

    _role_deleted_by: Mapped[List[User]] = relationship("User", foreign_keys=[role_deleted_by])
    _role_created_by: Mapped[List[User]] = relationship("User", foreign_keys=[role_created_by])

    _permissions: Mapped[List["Permissions"]] = relationship(
        "Permissions",
        back_populates="_role_permissions",
        secondary=middle_table_roles_permissions)

    def make_role(role: RequestRole, user: User):
        return Role(
            role_name=role.role_name,
            role_description=role.role_description,
            role_code=role.role_code,
            role_created_by=user.id
            )
    
    def apply_changes(self, new_params: UpdateRole):
        self.role_code = new_params.role_code if new_params.role_code else self.role_code
        self.role_name = new_params.role_name if new_params.role_name else self.role_name
        self.role_description = new_params.role_description if new_params.role_description else self.role_description

    def soft_delete(self, user: User):
        self.role_deleted_at = datetime.now()
        self._role_deleted_by = user

    def restore_soft(self):
        self.role_deleted_at = None
        self._role_deleted_by = None

    def add_permission(self, permission: Permissions):
        if permission not in self._permissions:
            self._permissions.append(permission)

    def add_permission_list(self, permission: list[Permissions]):
        for i in permission:
            self.add_permission(i)


class Permissions(Base):
    __tablename__ = "role_permission"

    id: Mapped[UUID] = mapped_column(UUID, unique=True, primary_key=True, default=uuid4)
    permission_name: Mapped[str] = mapped_column(String, unique=True)
    permission_description: Mapped[str] = mapped_column(String)
    permission_code: Mapped[str] = mapped_column(String(256), unique=True)
    permission_created_at: Mapped[date] = mapped_column(DateTime, default=datetime.now)
    permission_created_by: Mapped["User"] = mapped_column(ForeignKey("user_account.id"), nullable=True, default=None)
    permission_deleted_at: Mapped[date] = mapped_column(Date, nullable=True, default=None)
    permission_deleted_by: Mapped["User"] = mapped_column(ForeignKey("user_account.id"), nullable=True, default=None)

    _role_permissions: Mapped[List[Role]] = relationship("Role", back_populates="_permissions", secondary=middle_table_roles_permissions)
    _user_created_by: Mapped[List[User]] = relationship("User", foreign_keys=[permission_created_by])
    _user_deleted_by: Mapped[List[User]] = relationship("User", foreign_keys=[permission_deleted_by])

    def make_permission(permission: RequestPermission, user: User):
        return Permissions(
            permission_name=permission.permission_name,
            permission_description=permission.permission_description,
            permission_code=permission.permission_code,
            permission_created_by=user.id
            )
    
    def apply_changes(self, new_params: UpdatePermission):
        self.permission_code = new_params.permission_code if new_params.permission_code else self.permission_code
        self.permission_name = new_params.permission_name if new_params.permission_name else self.permission_name
        self.permission_description = new_params.permission_description if new_params.permission_description else self.permission_description

    def soft_delete(self, user: User):
        self.permission_deleted_at = datetime.now()
        self._user_deleted_by = user

    def restore_soft(self):
        self.permission_deleted_at = None
        self._user_deleted_by = None


class UserToken(HashModel):
    user: str
    toekn: str