from pydantic import BaseModel


class Todo(BaseModel):
    title: str
    description: str

#User document
class User(BaseModel):
    id:int
    username:str
    password:str
    habits:list | None = None


class Habit(BaseModel):
    id: int | None = None
    title:str  | None = None
    description:str | None = None


class UserInDB(User):
    hashed_password:str

