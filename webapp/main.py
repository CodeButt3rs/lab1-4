import fastapi
from fastapi import Request, FastAPI, APIRouter
from .models.models import *

app = FastAPI()
info_router = APIRouter(prefix='/info')

@info_router.get("/server")
def get_fastapi_version():
    return VersionInfoModel(version=fastapi.__version__)

@info_router.get("/client")
def get_client_info(request: Request):
    return UserInfoModel(user=request.headers.get("user-agent"))

@info_router.get("/database")
def get_database_info():
    return DatabaseInfoModel()

app.include_router(info_router)