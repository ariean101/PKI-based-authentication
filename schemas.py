from pydantic import BaseModel, Field


class UserRegister(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    phone: str = Field(min_length=10, max_length=15)
    password: str = Field(min_length=6, max_length=100)