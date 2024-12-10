import re

from pydantic import BaseModel, field_validator, ValidationInfo
from typing import Optional
from fastapi.exceptions import HTTPException
from datetime import date

latin_alphabet_lower = set('abcdefghijklmnopqrstuvwxyz')
latin_alphabet_upper = set('abcdefghijklmnopqrstuvwxyz'.upper())
latin_alphabet_full = latin_alphabet_upper | latin_alphabet_lower
symbols = {'~', ':', "'", '+', '[', '\\', '@', '^', '{', '%', '(', '-', '"', '*', '|', ',', '&', '<', '`', '}', '.', '_', '=', ']', '!', '>', ';', '?', '#', '$', ')', '/'}
digits = set("1234567890")


class VersionInfoModel(BaseModel):
    version: str

class UserInfoModel(BaseModel):
    user: str

class DatabaseInfoModel(BaseModel):
    database: Optional[str] = None

class LoginRequest(BaseModel):
    username: str

class RegisterUser(BaseModel):
    user_name: str
    user_password: str
    email: str
    c_password: str
    birthday: date

    @field_validator('user_name')
    @classmethod
    def user_name_validation(cls, user_name: str):
        if not (user_name[0].isupper() \
            and len(set(user_name) & latin_alphabet_full) == len(set(user_name)) \
            and len(user_name) >= 7):
            raise HTTPException(
                status_code=400, 
                detail="Username must contains only latin letters, be last 7 letters long and starts with capital letter"
                )
        return user_name
    
    @field_validator('user_password')
    @classmethod
    def user_password_validation(cls, user_password: str):
        if not(
            len(set(user_password) & latin_alphabet_lower) > 0 and len(set(user_password) & latin_alphabet_upper) > 0 \
            and set(user_password) & digits \
            and set(user_password) & symbols \
            and len(user_password) >= 8
            ):
            raise HTTPException(
                status_code=400, 
                detail="Password must contains at 1 upper and 1 lower case letter \
                        , be last 8 characters long, include at least 1 digit and 1 special character"
                )
        return user_password
    
    @field_validator('c_password')
    @classmethod
    def user_control_password(cls, c_password: str, values: ValidationInfo):
        if (values.data.get('user_password') != c_password):
            raise HTTPException(status_code=400, detail="Password must match")
        return c_password
    
    @field_validator('email')
    @classmethod
    def user_email_validation(cls, email: str):
        if not re.match(string=email, pattern=r"^\S+@\S+\.\S+$"):
            raise HTTPException(status_code=400, detail="Incorrect email")
        return email


class AuthUser(BaseModel):
    user_name: str
    user_password: str

class TokenUser(BaseModel):
    user_name: str
    token: str

class RequestRole(BaseModel):
    role_name: str
    role_description: str
    role_code: str

class UpdateRole(BaseModel):
    role_id: str
    role_name: str | None = None
    role_description: str | None = None
    role_code: str | None = None

class RequestPermission(BaseModel):
    permission_name: str
    permission_description: str
    permission_code: str

class UpdatePermission(BaseModel):
    permission_id: str
    permission_name: str | None = None
    permission_description: str | None = None
    permission_code: str | None = None
    permission_roles: list[str] | None = None