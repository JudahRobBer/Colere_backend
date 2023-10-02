#data model
from model import Todo, User, Habit, UserInDB

#mongoDB driver
import motor.motor_asyncio

#connect to mongodb server connection on computer
client = motor.motor_asyncio.AsyncIOMotorClient('mongodb://localhost:27017')


#each document is a user with habits as embeddded documents
#ON JUDAH MAC
database = client.Colere
collection = database.Users

#ON REAL SERVER
#database = client.colere
#collection = database.users


#new database methods

async def create_user(user: dict()):
    document = user
    #get current user_count
    count = await collection.count_documents({})
    document["id"] = count
    if document["habits"][0] == "string":
        document["habits"] = []
    
    result = collection.insert_one(document)
    return user

async def delete_user(username:str):
    result = await collection.delete_one({'username':username})
    return True


async def get_user(username:str):
    document = await collection.find_one({'username':username})
    if document:
        return User(**document)
    #return UserInDB(**document)

#is this return necessary?
async def update_user_password(username:str, password:str):
    result = await collection.update_one({'username':username},{"$set":{"password":password}})
    document = await collection.find_one({'username':username})
    return document


async def create_user_habit(username:str,new_habit:dict):
    #get the current size of habit list
    document = await collection.find_one({'username':username})
    if document:
        habit_count = len(document["habits"])
        new_habit["id"] = habit_count
    
        result = await collection.update_one({'username':username}, {"$push": {"habits":new_habit}})
    
        #document has been updated, and updated version must be found again
        document = await collection.find_one({'username':username})

    return document


#find the old habit from the list using the updated_habits id
#for this to function, YOU MUST CREATE THE UPDATED HABIT WITH THE ID OF THE OLD HABIT
#remove the old habit
#add the new habit
async def update_user_habit(username:str,updated_habit:dict):
    #old_habit = await collection.find_one({"username":username},{"habits":{"id":updated_habit["id"]}})
    #for key,value in updated_habit:
     #   if value == None or "string":
      #      if old_habit[str(key)] is not None:
       #         updated_habit[key] = old_habit[str(key)]
    
    remove_old_habit = await collection.update_one({'username':username},{"$pull":{"habits":{"id":updated_habit["id"]}}})
    add_new_habit =  await collection.update_one({'username':username},{"$push":{"habits":updated_habit}})
    
    document = await collection.find_one({'username':username},{"habits":updated_habit})
    return document


#deletes habit by habit id
#passes in whole habit for consistency? should likely be changed
async def delete_user_habit(username:str,habit_id:int):
    result = await collection.update_one({'username':username},{"$pull":{"habits":{"id":habit_id}}})
    return True
   


async def get_all_user_habits(username:str) -> list:
    cursor = await collection.find_one({'username':username})
    habits = cursor["habits"]
    
    for i in range(len(habits)):
        habits[i] = Habit(**habits[i])
    
    return habits


async def get_user_habit_by_id(username:str,habit_id:int):
    habit = await collection.find_one({'username':username},{"habits":{"id":habit_id}})
    return habit
    
