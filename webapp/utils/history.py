# from __future__ import annotations
# import fastapi
# from ..database.database import database_mgr as db_mgr
# from ..database.models import Base, User, Permissions, Role
# from sqlalchemy.ext.serializer import dumps

# entity_get = {
#     User: db_mgr.postgresql.get_user_by_id,
#     Permissions: db_mgr.get_permission_by_id,
#     Role: db_mgr.get_role_by_id
# }

def make_record(entity_type, entity_id: str):
    entity_get = {
    User: db_mgr.postgresql.get_user_by_id,
    Permissions: db_mgr.get_permission_by_id,
    Role: db_mgr.get_role_by_id
}

    def wrapper(fnc, *args, **kwargs):
        try: 
            previous_data: Base = entity_get[entity_type](kwargs.get(entity_id))
            user = db_mgr.get_user(kwargs.get('usern_name'))
            jsoned_data = dumps(previous_data)
            fnc(*args, **kwargs)
            db_mgr.make_history_record(entity_type, user, jsoned_data)
        except Exception as e:
            raise e
    return wrapper