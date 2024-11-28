from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from redis_om import HashModel
from uuid import UUID, uuid4
from datetime import date
from ..models.models import RegisterUser
import sqlalchemy
import hashlib

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "user_account"

    id: Mapped[UUID] = mapped_column(sqlalchemy.UUID, unique=True, primary_key=True, default=uuid4)
    user_name: Mapped[str] = mapped_column(sqlalchemy.String, unique=True)
    user_password: Mapped[str] = mapped_column(sqlalchemy.String(256))
    user_email: Mapped[str] = mapped_column(sqlalchemy.String(256), unique=True)
    user_birthday: Mapped[date] = mapped_column(sqlalchemy.Date)

    def user_hash(self):
        return hashlib.sha256(str(self.id).encode(encoding='utf-8', errors = 'strict')).hexdigest()
    
    def password_hash(password_str):
        return hashlib.sha256(password_str.encode(encoding = 'UTF-8', errors = 'strict')).hexdigest()
    
    def make_user(user: RegisterUser):
        return User(
            user_name=user.user_name, 
            user_password=User.password_hash(user.user_password),
            user_email=user.email,
            user_birthday=user.birthday
            )


class UserToken(HashModel):
    user: str
    toekn: str