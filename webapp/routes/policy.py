from typing import Annotated
from fastapi import Request, APIRouter, Depends, exceptions
from uuid import UUID
from ..models.models import *
from ..utils.dependecies import auth_required
from ..database.database import database_mgr


policy_router = APIRouter(prefix='/ref/policy')

@policy_router.get("/role", dependencies=[Depends(auth_required)])
def roles_list(request: Request):
    return database_mgr.get_all_roles()

@policy_router.post("/role", dependencies=[Depends(auth_required)])
def create_role(request: Request, role: RequestRole, user: Annotated[dict, Depends(auth_required)]):
    return database_mgr.create_role(role, user.get("user_name"))

@policy_router.get("/role/{id}", dependencies=[Depends(auth_required)])
def get_role(request: Request, id: UUID):
    return database_mgr.get_role_by_id(id)

@policy_router.put("/role/{id}", dependencies=[Depends(auth_required)])
def update_role(request: Request, id: str, role: RequestRole, user: Annotated[dict, Depends(auth_required)]):
    return database_mgr.update_role(id, role, user.get("user_name"))

@policy_router.delete("/role/{id}", dependencies=[Depends(auth_required)])
def delete_role_hard(request: Request):
    return 1

@policy_router.delete("/role/{id}/soft")
def delete_role_soft(request: Request):
    return 1

@policy_router.post("/role/{id}/restore")
def restore_soft_deleted_role(request: Request):
    return 1

# Permissions

@policy_router.get("/premission", dependencies=[Depends(auth_required)])
def premission_list(request: Request):
    return 1 

@policy_router.get("/premission/{id}", dependencies=[Depends(auth_required)])
def get_premission(request: Request):
    return 1

@policy_router.post("/premission/", dependencies=[Depends(auth_required)])
def create_premission(request: Request):
    return 1

@policy_router.put("/premission/{id}", dependencies=[Depends(auth_required)])
def update_premission(request: Request):
    return 1

@policy_router.delete("/premission/{id}", dependencies=[Depends(auth_required)])
def delete_premission_hard(request: Request):
    return 1

@policy_router.delete("/premission/{id}/soft")
def delete_premission_soft(request: Request):
    return 1

@policy_router.post("/premission/{id}/restore")
def restore_soft_deleted_premission(request: Request):
    return 1

# User

user_policy_router = APIRouter(prefix='/ref/user')

@user_policy_router.get("/", dependencies=[Depends(auth_required)])
def user_list(request: Request):
    return 1 

@user_policy_router.get("/{id}/role", dependencies=[Depends(auth_required)])
def get_user_roles(request: Request):
    return 1

@user_policy_router.post("/{id}/role", dependencies=[Depends(auth_required)])
def set_user_user(request: Request):
    return 1

@user_policy_router.delete("/{id}/role/{role_id}", dependencies=[Depends(auth_required)])
def delete_user_role_hard(request: Request):
    return 1

@user_policy_router.delete("/{id}/role/{role_id}/soft")
def delete_user_role_soft(request: Request):
    return 1

@user_policy_router.post("/{id}/role/{role_id}/restore")
def restore_soft_deleted_user_role(request: Request):
    return 1