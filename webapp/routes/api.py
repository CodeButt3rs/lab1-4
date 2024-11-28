from typing import Annotated
from fastapi import Request, APIRouter, Depends, exceptions

from ..models.models import *
from ..utils.dependecies import auth_required
from ..database.database import database_mgr


auth_router = APIRouter(prefix='/api/auth')

@auth_router.post("/login")
def login_user(request: Request, user: AuthUser):
    return {'Bearer-token': database_mgr.auth_user_by_log_pass(user)} 

@auth_router.post("/register")
def register_user(request: Request, user: RegisterUser):
    return database_mgr.register_user(user)

@auth_router.get("/me", dependencies=[Depends(auth_required)])
def get_user_profile(request: Request, user: Annotated[dict, Depends(auth_required)]):
    return database_mgr.get_user(user['user_name'])

@auth_router.post("/logout", dependencies=[Depends(auth_required)])
def logout_token(request: Request, user: Annotated[dict, Depends(auth_required)]):
    result = database_mgr.delete_token(database_mgr.get_user(user['user_name'])) 
    if not result:
        raise exceptions.HTTPException(status_code=403, detail='Not allowed')
    return {"status": "Success"}

@auth_router.get("/tokens", dependencies=[Depends(auth_required)])
def get_user_tokens(request: Request, user: Annotated[dict, Depends(auth_required)]):
    raise exceptions.HTTPException(status_code=403, detail='Not allowed')

@auth_router.post("/out_all")
def logout_user_tokens(request: Request):
    raise exceptions.HTTPException(status_code=403, detail='Not allowed')
