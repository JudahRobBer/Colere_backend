#data model
from model import Todo

#mongoDB driver
import motor.motor_asyncio

#connect to mongodb server connection on computer
client = motor.motor_asyncio.AsyncIOMotorClient('mongodb://localhost:27017')

database = client.TodoList
collection = database.todo

#get the todo by title from database
async def fetch_one_todo(title):
    document = await collection.find_one({"title":title})
    return document

#get all todos in database
async def fetch_all_todos():
    todos = []
    #find with empty document gets all
    cursor = collection.find({})
    #async for loop?
    async for document in cursor:
        #dereference document pointer and cast to Todo class
        todos.append(Todo(**document))
    return todos

async def create_todo(todo):
    document = todo
    result = await collection.insert_one(document)
    return document

async def update_todo(title,desc):
    await collection.update_one({"title":title},
                                {"$set":{"description":desc}})
    document = await collection.find_one({"title":title})
    return document

async def remove_todo(title):
    await collection.delete_one({"title":title})
    return True


