from fastapi import FastAPI, HTTPException
#enables frontend to communicate with backend on different ports
from fastapi.middleware.cors import CORSMiddleware
from model import Todo

#backend app object
app = FastAPI()

from database import (
    fetch_one_todo,
    fetch_all_todos,
    create_todo,
    update_todo,
    remove_todo
)

#where you can access app from?
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ["*"], #get, post?
    allow_headers = ["*"]
)

#indicates where the given function is accessed
#in this case it is root
@app.get("/")
def read_root():
    return {"Ping":'Pong'}

#for tutorial we need: post, update, get, delete

@app.get("/api/todo")
async def get_todo():
    response = await fetch_all_todos()
    return response

@app.get("/api/todo{title}", response_model=Todo)
async def get_todo_by_id(title):
    response = await fetch_one_todo(title)
    if response:
        return response
    raise HTTPException(404,f"There is no todo item with this title {title}")

@app.post("/api/todo", response_model=Todo)
async def post_todo(todo:Todo):
    response = await create_todo(todo.model_dump())
    if response:
        return response
    raise HTTPException(400,"Something went wrong")

@app.put("/api/todo{title}",response_model=Todo)
async def put_todo(title:str,desc:str):
    response = await update_todo(title,desc)
    if response:
        return response
    raise HTTPException(404,f"There is no todo item with this title {title}")

@app.delete("/api/todo{title}")
async def delete_todo(title):
    response = await remove_todo(title)
    if response:
        return "Succesfully deleted todo item!"
    raise HTTPException(404,f"There is no todo item with this title {title}")