from fastapi import FastAPI
from .models.models import *
from .routes.info import info_router
from .routes.api import auth_router
from .routes.policy import policy_router, user_policy_router
# from .database.database import DatabaseManager


class MainApp(FastAPI):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.include_router(info_router)
        self.include_router(auth_router)
        self.include_router(policy_router)
        self.include_router(user_policy_router)

app = MainApp()
