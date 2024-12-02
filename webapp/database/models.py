from __future__ import annotations
import sqlalchemy.event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, registry, Session, scoped_session, sessionmaker
from sqlalchemy.dialects.postgresql import UUID
from redis_om import HashModel
from uuid import UUID, uuid4
from datetime import date
from ..models.models import RegisterUser, RequestRole, UpdateRole
from typing import List
from datetime import datetime
import sqlalchemy
import hashlib
import random


class Base(DeclarativeBase):
    pass


middle_table_roles_permissions = sqlalchemy.Table(
    "roles_permissions",
    Base.metadata,
    sqlalchemy.Column("role_id", sqlalchemy.ForeignKey("user_role.id")),
    sqlalchemy.Column("permission_id", sqlalchemy.ForeignKey("role_permission.id"))
)

class User(Base):
    __tablename__ = "user_account"

    id: Mapped[UUID] = mapped_column(sqlalchemy.UUID, unique=True, primary_key=True, default=uuid4)
    user_name: Mapped[str] = mapped_column(sqlalchemy.String, unique=True)
    user_password: Mapped[str] = mapped_column(sqlalchemy.String(256))
    user_email: Mapped[str] = mapped_column(sqlalchemy.String(256), unique=True)
    user_birthday: Mapped[date] = mapped_column(sqlalchemy.Date)
    user_role: Mapped["Role"] = mapped_column(sqlalchemy.ForeignKey("user_role.id"), nullable=True)

    Role: Mapped["Role"] = relationship("Role", foreign_keys=[user_role])

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


class Role(Base):
    __tablename__ = "user_role"

    id: Mapped[UUID] = mapped_column(sqlalchemy.UUID, unique=True, primary_key=True, default=uuid4)
    role_name: Mapped[str] = mapped_column(sqlalchemy.String, unique=True)
    role_description: Mapped[str] = mapped_column(sqlalchemy.String)
    role_code: Mapped[str] = mapped_column(sqlalchemy.String(256), unique=True)
    role_created_at: Mapped[date] = mapped_column(sqlalchemy.DateTime, default=datetime.now)
    role_created_by: Mapped["User"] = mapped_column(sqlalchemy.ForeignKey("user_account.id"), nullable=True, default=None)
    role_deleted_at: Mapped[date] = mapped_column(sqlalchemy.Date, nullable=True, default=None)
    role_deleted_by: Mapped["User"] = mapped_column(sqlalchemy.ForeignKey("user_account.id"), nullable=True, default=None)

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
        self.role_code = new_params.role_code
        self.role_name = new_params.role_name
        self.role_description = new_params.role_description

class Permissions(Base):
    __tablename__ = "role_permission"

    id: Mapped[UUID] = mapped_column(sqlalchemy.UUID, unique=True, primary_key=True, default=uuid4)
    permission_name: Mapped[str] = mapped_column(sqlalchemy.String, unique=True)
    permission_description: Mapped[str] = mapped_column(sqlalchemy.String)
    permission_code: Mapped[str] = mapped_column(sqlalchemy.String(256), unique=True)
    permission_created_at: Mapped[date] = mapped_column(sqlalchemy.DateTime, default=datetime.now)
    permission_created_by: Mapped["User"] = mapped_column(sqlalchemy.ForeignKey("user_account.id"), nullable=True, default=None)
    permission_deleted_at: Mapped[date] = mapped_column(sqlalchemy.Date, nullable=True, default=None)
    permission_deleted_by: Mapped["User"] = mapped_column(sqlalchemy.ForeignKey("user_account.id"), nullable=True, default=None)

    _role_permissions: Mapped[List[Role]] = relationship("Role", back_populates="_permissions", secondary=middle_table_roles_permissions)
    _user_created_by: Mapped[List[User]] = relationship("User", foreign_keys=[permission_created_by])
    _user_deleted_by: Mapped[List[User]] = relationship("User", foreign_keys=[permission_deleted_by])

@sqlalchemy.event.listens_for(Base.metadata, 'after_create')
def insert_default_data(target, connection: sqlalchemy.Connection, **kwargs):
    session = scoped_session(sessionmaker(autoflush=False, autocommit=False))
    session.configure(bind=connection)
    
    sys_admin_password = hashlib.sha256(f'{str(random.randrange(10000, 100000000000000))}'.encode(encoding='utf-8')).hexdigest() + "!Ab"

    sys_admin: User = User.make_user(RegisterUser(
        user_name='SYSTEMADMIN',
        user_password=sys_admin_password,
        c_password=sys_admin_password,
        email="system111@mail.com",
        birthday='2000-01-01'
    ))

    session.add(sys_admin)
    session.commit()
    session.refresh(sys_admin)

    default_role: Role = Role.make_role(RequestRole(
        role_name="Guest",
        role_description="Default role",
        role_code="DEFAULT_GUEST",
        role_created_by=sys_admin.id
    ),
        user=sys_admin
        )
    
    admin_role: Role = Role.make_role(RequestRole(
        role_name="Admin",
        role_description="SYSTEM_ADMIN",
        role_code="SYSTEM_ADMIN",
    ),
        user=sys_admin
        )
    
    session.add_all([default_role, admin_role])
    session.commit()
    session.refresh(admin_role)

    sys_admin.Role = admin_role

    session.commit()
    session.flush()
    session.close()

class UserToken(HashModel):
    user: str
    toekn: str