from pydantic import BaseModel
from typing import Optional


class VersionInfoModel(BaseModel):
    version: str

class UserInfoModel(BaseModel):
    user: str

class DatabaseInfoModel(BaseModel):
    database: Optional[str] = None