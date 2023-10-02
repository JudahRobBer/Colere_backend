from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader
#enables frontend to communicate with backend on different ports
from fastapi.middleware.cors import CORSMiddleware
from model import  User, Habit, Token, TokenData


from jose import JWTError, jwt
from passlib.context import CryptContext


import database


api_keys = [
    "my_api_key"
]

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

api_key_header = APIKeyHeader(name="X-API-Key")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)


def get_api_key(api_key_header: str = Security(api_key_header)) -> str:
    if api_key_header in api_keys:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)

#given a database and a username
#return a UserInDB with a User object as input
#def get_user(db, username: str):
 #   if username in db:
  #      user_dict = db[username]
   #     return UserInDB(**user_dict)

#confirm the user exists in the database and the hashed password matches the input
#if so, return the UserInDB object
#this needs to be rewritten in the database file


async def authenticate_user(username: str, password: str):
    #not working, "coroutine object has no attribute "
    user = await database.get_user(username)
    
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


#password flow: User enters username and password into frontend,
#frontend sends data to url in API, API verifies data, returns token
#token is stored by frontend, is sent to backend when user requests more data
#token is temporary
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


#once the token has been created, the front end sends it
#this token is associated with a particular user
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = await database.get_user(username=token_data.username)
    #user = User(**user)
    if user is None:
        raise credentials_exception
    return user


#handles user "disabled" label
async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

#@app.get("/api/protected")
#def protected_route(api_key: str = Security(get_api_key)):
    #Process the request for authenticated accesses
 #   return {"message": "Access granted!"}

#an api key security in this method causes issues in other methods
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
    #api_key:str = Security(get_api_key)
):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
    api_key:str = Security(get_api_key)
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"item_id": "Foo", "owner": current_user.username}]


#indicates where the given function is accessed
#in this case it is root



#last reference method!
#@app.put("/api/todo{title}",response_model=Todo)
#async def put_todo(title:str,desc:str):
 #   response = await update_todo(title,desc)
 #   if response:
  #      return response
   # raise HTTPException(404,f"There is no todo item with this title {title}")



#post methods

@app.post("/api/users",response_model=User)
async def create_user(user:User,api_key: str = Security(get_api_key)):
    user.password = get_password_hash(user.password)
    response = await database.create_user(user.model_dump())
    if response:
        return response


#works but returns internal server error??
@app.post("/api/users", response_model=Habit)
async def create_user_habit(current_user: Annotated[User, Depends(get_current_active_user)], habit:Habit,api_key: str = Security(get_api_key)):
    response = await database.create_user_habit(current_user.username,habit.model_dump())
    if response:
        return response
    raise HTTPException(400,"Error Creating Habit")


#get methods

@app.get("/api/users",response_model=User)
async def get_user(current_user: Annotated[User, Depends(get_current_active_user)], api_key: str = Security(get_api_key)):
    result = await database.get_user(current_user.username)
    if result:
        return result
    raise HTTPException(404, "User could not be found")


@app.get("/api/users/habit{habit_id}", response_model = Habit)
async def get_user_habit_by_id(current_user: Annotated[User, Depends(get_current_active_user)],habit_id:int,api_key: str = Security(get_api_key)):
    response = await database.get_user_habit_by_id(current_user.username,int(habit_id))
    if response:
        return response
    raise HTTPException(404,f"User {current_user.username} has no abit item with this id {habit_id}")


@app.get("/api/users/habit")
async def get_all_user_habits(current_user: Annotated[User, Depends(get_current_active_user)],api_key: str = Security(get_api_key)):
    response = await database.get_all_user_habits(current_user.username)
    return response


#update methods


#update user password


#@app.get("api/user{user}/habit{habit}", response_model = Habit)
#async def update_user_habit(username:str, habit:Habit):
#    response = await database.update_user_habit(username,habit.model_dump())
 #   if response:
 #       return response
  #  raise HTTPException(400,"Unable to update Habit")


#delete methods

#habit itself is passed in, rather than identifier. Change to pass in ID?
@app.delete("/api/users/habits{habit_id}")
async def delete_user_habit(current_user: Annotated[User, Depends(get_current_active_user)],habit_id:int, api_key: str = Security(get_api_key)):
    response = await database.delete_user_habit(current_user.username,int(habit_id))
    if response:
        return f"Succesfully delete habit {habit_id} from user {current_user.username}"
    HTTPException(404,f"User {current_user.username} has no habit with this id {habit_id}")

#works
@app.delete("/api/users")
async def delete_user(current_user: Annotated[User, Depends(get_current_active_user)], api_key: str = Security(get_api_key)):
    response = await database.delete_user(current_user.username)
    if response:
        return f"Sucessfully deleted User"
    raise HTTPException(404,"User was not deleted")