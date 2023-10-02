from pydantic import BaseModel


class Todo(BaseModel):
    title: str
    description: str

#User document
class User(BaseModel):
    id:int | None = None
    username:str | None = None
    password:str | None = None
    habits:list | None = None
    disabled: bool | None = False


class Habit(BaseModel):
    id: int | None = None
    title:str  | None = None
    description:str | None = None


class UserInDB(User):
    hashed_password:str

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

