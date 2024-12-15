from typing import Annotated
from fastapi import Request, APIRouter, Depends, exceptions
from uuid import UUID
from ..models.models import *
from ..utils.dependecies import auth_required, PermissionDependnecy
from ..database.database import database_mgr
from ..utils.history import make_history

get_user_list = PermissionDependnecy('GET_USER_ALL')
get_user_self = PermissionDependnecy('GET_USER_SELF')
get_user_roles = PermissionDependnecy('GET_USER_ROLES')
get_role_list = PermissionDependnecy('GET_ROLE_ALL')
get_permission_list = PermissionDependnecy('GET_PERMISSION_ALL')
edit_permission = PermissionDependnecy('EDIT_PERMISSION')
edit_role = PermissionDependnecy('EDIT_ROLE')
delete_permission = PermissionDependnecy('DELETE_PERMISSION')
delete_role = PermissionDependnecy('DELETE_ROLE')
set_role = PermissionDependnecy('SET_ROLE')
add_permission = PermissionDependnecy('ADD_PERMISSION')
remove_permission = PermissionDependnecy('REMOVE_PERMISSION')
edit_user_self = PermissionDependnecy('EDIT_USER_SELF')

policy_router = APIRouter(prefix='/ref/policy')

@policy_router.get("/role", dependencies=[Depends(get_user_list)])
def roles_list(request: Request):
    return database_mgr.get_all_roles()

@policy_router.post("/role", dependencies=[Depends(edit_role)])
def create_role(request: Request, role: RequestRole, user: Annotated[dict, Depends(edit_role)]):
    return database_mgr.create_role(role, user.get("user_name"))

@policy_router.get("/role/{id}", dependencies=[Depends(get_role_list)])
def get_role(request: Request, id: UUID):
    return database_mgr.get_role_by_id(id)

@policy_router.put("/role/{id}", dependencies=[Depends(edit_role)])
def update_role(request: Request, id: str, role: UpdateRole):
    return database_mgr.update_role(id, role)

@policy_router.delete("/role/{id}", dependencies=[Depends(delete_role)])
def delete_role_hard(request: Request, id: str):
    return database_mgr.delete_permission_hard(id)

@policy_router.delete("/role/{id}/soft")
def delete_role_soft(request: Request, id: str, user: Annotated[dict, Depends(delete_role)]):
    return database_mgr.delete_role_soft(id, user.get("user_name"))

@policy_router.post("/role/{id}/restore", dependencies=[Depends(edit_role)])
def restore_soft_deleted_role(request: Request, id: str):
    return database_mgr.restore_role_soft(id)

@policy_router.post("/role/{role_id}/add_permission/{permission_id}", dependencies=[Depends(add_permission)])
def add_permission_to_role(request: Request, role_id: str, permission_id: str):
    return database_mgr.add_permission_role(role_id, permission_id)

# Permissions

@policy_router.get("/permission", dependencies=[Depends(get_permission_list)])
def permission_list(request: Request):
    return database_mgr.get_all_permissions()

@policy_router.get("/permission/{id}", dependencies=[Depends(get_permission_list)])
def get_permission(request: Request, id: UUID):
    return database_mgr.get_permission_by_id(id)

@policy_router.post("/permission", dependencies=[Depends(edit_permission)])
def create_permission(request: Request, permission: RequestPermission, user: Annotated[dict, Depends(edit_permission)]):
    return database_mgr.create_permission(permission, user.get("user_name"))

@policy_router.put("/permission/{id}", dependencies=[Depends(edit_permission)])
def update_permission(request: Request, id: str, permission: UpdatePermission, user: Annotated[dict, Depends(edit_permission)]):
    return database_mgr.update_permission(id, permission, user['user_name'])

@policy_router.delete("/permission/{id}", dependencies=[Depends(delete_permission)])
def delete_permission_hard(request: Request, id: str):
    return database_mgr.delete_permission_hard(id)

@policy_router.delete("/permission/{id}/soft", dependencies=[Depends(delete_permission)])
def delete_permission_soft(request: Request, id: str, user: Annotated[dict, Depends(delete_permission)]):
    return database_mgr.delete_permission_soft(id, user.get("user_name"))

@policy_router.post("/permission/{id}/restore", dependencies=[Depends(delete_permission)])
def restore_soft_deleted_permission(request: Request, id: str):
    return database_mgr.restore_permission_soft(id)

# User

user_policy_router = APIRouter(prefix='/ref/user')

@user_policy_router.get("/", dependencies=[Depends(get_user_list)])
def user_list(request: Request):
    return database_mgr.get_users_list()

@user_policy_router.get("/{id}/role", dependencies=[Depends(get_user_roles)])
def get_user_roles(request: Request, user: Annotated[dict, Depends(get_user_roles)]):
    return database_mgr.get_user(user["user_name"])._role

@user_policy_router.post("/{user_id}/role/{role_id}", dependencies=[Depends(set_role)])
def set_user_role(request: Request, user_id: str, role_id: str):
    return database_mgr.set_user_role(user_id, role_id)

@user_policy_router.delete("/{id}/role", dependencies=[Depends(set_role)])
def delete_user_role_hard(request: Request, id: str):
    return database_mgr.reset_user_role(id)

# @user_policy_router.delete("/{id}/role/{role_id}/soft")
# def delete_user_role_soft(request: Request):
#     return 1

# @user_policy_router.post("/{id}/role/{role_id}/restore")
# def restore_soft_deleted_user_role(request: Request):
#     return 1