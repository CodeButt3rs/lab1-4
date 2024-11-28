from fastapi.exceptions import HTTPException
from ..database.database import database_mgr
from ..models.models import TokenUser


def auth_required(user: TokenUser):
    if not database_mgr.verify_token(user.user_name, user.token):
        raise HTTPException(status_code=403, detail='Invalid token')
    return user.model_dump()