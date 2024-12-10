from __future__ import annotations
import sqlalchemy
import random
import hashlib
from .models import Base, User, Role, Permissions, RegisterUser, RequestRole, RequestPermission
from sqlalchemy import Connection, select
from sqlalchemy.orm import scoped_session, sessionmaker


@sqlalchemy.event.listens_for(Base.metadata, 'after_create')
def insert_default_data(target, connection: Connection, **kwargs):

    users: list[User] = []
    roles: list[Role] = []
    permissions: list[Permissions] = []

    session = scoped_session(sessionmaker(autoflush=False, autocommit=False))
    session.configure(bind=connection)
    if session.scalars(select(User).where(User.user_name == "SYSTEMADMIN")).one_or_none():
        return
    sys_admin_password = hashlib.sha256(
        f'{str(random.randrange(10000, 100000000000000))}'.encode(encoding='utf-8')).hexdigest() + "!Ab"
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

    guest_role: Role = Role.make_role(RequestRole(
        role_name="Guest",
        role_description="Роль гостя",
        role_code="GUEST_DEFAULT",
        role_created_by=sys_admin.id
        ),
        user=sys_admin
    )
    
    user_role: Role = Role.make_role(RequestRole(
        role_name="User",
        role_description="Роль обычного пользователя",
        role_code="USER_DEFAULT",
        role_created_by=sys_admin.id
        ),
        user=sys_admin
    )

    admin_role: Role = Role.make_role(RequestRole(
        role_name="Admin",
        role_description="Роль системного админа",
        role_code="SYSTEM_ADMIN",
        ),
        user=sys_admin
    )
    # PERMISSIONS
    get_user_list = Permissions.make_permission(
        RequestPermission(
            permission_name="Получить список пользователей",
            permission_description="Разрешает получить список пользователей",
            permission_code="GET_USER_ALL"
        ),
        sys_admin
    )
    get_user_self = Permissions.make_permission(
        RequestPermission(
            permission_name="Получить информацию о себе",
            permission_description="Разрешает получить информацию о себе",
            permission_code="GET_USER_SELF"
        ),
        sys_admin
    )
    get_user_roles = Permissions.make_permission(
        RequestPermission(
            permission_name="Получить роль определённого пользователя",
            permission_description="Разрешает получить роль определённого пользователя",
            permission_code="GET_USER_ROLE"
        ),
        sys_admin
    )
    get_role_list = Permissions.make_permission(
        RequestPermission(
            permission_name="Получить список всех ролей",
            permission_description="Разрешает получить список всех ролей",
            permission_code="GET_ROLE_ALL"
        ),
        sys_admin
    )
    get_permission_list = Permissions.make_permission(
        RequestPermission(
            permission_name="Получить список всех возможных разрешений",
            permission_description="Разрешает получить список всех возможных разрешений",
            permission_code="GET_PERMISSION_ALL"
        ),
        sys_admin
    )
    edit_permission = Permissions.make_permission(
        RequestPermission(
            permission_name="Редактирование разрешений (допусков)",
            permission_description="Разрешает редактировать разрешения (допуски)",
            permission_code="EDIT_PERMISSION"
        ),
        sys_admin
    )
    edit_role = Permissions.make_permission(
        RequestPermission(
            permission_name="Редактирование ролей",
            permission_description="Разрешает редактировать роли",
            permission_code="EDIT_ROLE"
        ),
        sys_admin
    )
    delete_permission = Permissions.make_permission(
        RequestPermission(
            permission_name="Удаление разрешений (допусков)",
            permission_description="Разрешает удалять разрешения (допуски)",
            permission_code="DELETE_PERMISSION"
        ),
        sys_admin
    )
    delete_role = Permissions.make_permission(
        RequestPermission(
            permission_name="Удаление ролей",
            permission_description="Разрешает удалять роли",
            permission_code="DELETE_ROLE"
        ),
        sys_admin
    )
    set_role = Permissions.make_permission(
        RequestPermission(
            permission_name="Установить роль",
            permission_description="Разрешает устанавливать роль пользователю",
            permission_code="SET_ROLE"
        ),
        sys_admin
    )
    add_permission = Permissions.make_permission(
        RequestPermission(
            permission_name="Добавить разрешение (допуск) роли",
            permission_description="Разрешает удалять разрешения (допуски) у роли",
            permission_code="ADD_PERMISSION"
        ),
        sys_admin
    )
    remove_permission = Permissions.make_permission(
        RequestPermission(
            permission_name="Убрать разрешение",
            permission_description="Разрешает убирать разрешения (допуски) у роли",
            permission_code="REMOVE_PERMISSION"
        ),
        sys_admin
    )
    edit_user_self = Permissions.make_permission(
        RequestPermission(
            permission_name="Редактирование данных самого пользователя",
            permission_description="Разрешает редактировать свои данные самому пользователю",
            permission_code="EDIT_USER_SELF"
        ),
        sys_admin
    )

    users.extend([sys_admin])
    roles.extend([user_role, admin_role, guest_role])
    permissions.extend([
        get_user_list, get_user_self, get_user_roles, get_role_list, get_permission_list, edit_permission,
        edit_role, delete_permission, delete_role, set_role, add_permission, remove_permission, edit_user_self
    ])

    admin_role.add_permission_list(permissions)
    user_role.add_permission_list(
        [get_user_self, edit_user_self, get_user_list]
    )
    guest_role.add_permission(get_user_list)

    session.add_all(users)
    session.add_all(permissions)
    session.add_all(roles)

    session.commit()
    session.refresh(admin_role)

    sys_admin._role = admin_role

    session.commit()
    session.flush()
    session.close()