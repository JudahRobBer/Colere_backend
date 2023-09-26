from pydantic import BaseModel


class Todo(BaseModel):
    title: str
    description: str


class User(BaseModel):
    username: str
    email: str
    hashed_password: str
    disabled: bool = False
    habits: list

class Habit(BaseModel):
    title:str
    description: str

