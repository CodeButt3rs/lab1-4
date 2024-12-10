from fastapi.exceptions import HTTPException
from ..database.database import database_mgr
from ..models.models import TokenUser
from typing import Annotated
from fastapi import Depends


def auth_required(user: TokenUser):
    if not database_mgr.verify_token(user.user_name, user.token):
        raise HTTPException(status_code=403, detail='Invalid token')
    return user.model_dump()


class PermissionDependnecy:
    def __init__(self, allowed_role):
        self.allowed_role = allowed_role

    def __call__(self, user: Annotated[dict, Depends(auth_required)]):
        if not database_mgr.check_user_access(user['user_name'], self.allowed_role):
            raise HTTPException(status_code=403, detail='You dont have permission for this request')
        return user