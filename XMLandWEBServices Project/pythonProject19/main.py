from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Dict, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

# Part 1: Import Statements and Initial Setup

app = FastAPI()

# Secret key for JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Part 2: Database Models and In-Memory Databases

item_database = {}
sample_database = {}
user_database = {}

class Item(BaseModel):
    name: str
    description: str

class Sample(BaseModel):
    id: int
    data: str

class User(BaseModel):
    username: str
    email: str
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Part 3: Authentication and Authorization

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(fake_db, username: str, password: str):
    user = fake_db.get(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
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
    user = user_database.get(token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(user_database, form_data.username, form_data.password)
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

# Part 4: Service 1 - Item Service

@app.post("/items/", dependencies=[Depends(get_current_active_user)])
def create_item(item: Item):
    item_database[item.name] = item
    return {"message": "Item created successfully", "item": item}

@app.get("/items/{name}", dependencies=[Depends(get_current_active_user)])
def read_item(name: str):
    if name not in item_database:
        raise HTTPException(status_code=404, detail="Item not found")
    return item_database[name]

@app.put("/items/{name}", dependencies=[Depends(get_current_active_user)])
def update_item(name: str, item: Item):
    if name not in item_database:
        raise HTTPException(status_code=404, detail="Item not found")
    item_database[name] = item
    return {"message": "Item updated successfully", "item": item}

@app.delete("/items/{name}", dependencies=[Depends(get_current_active_user)])
def delete_item(name: str):
    if name not in item_database:
        raise HTTPException(status_code=404, detail="Item not found")
    del item_database[name]

# Part 5: Service 2 - Sample Service

@app.post("/samples/", dependencies=[Depends(get_current_active_user)])
def create_sample(sample: Sample):
    sample_database[sample.id] = sample
    return {"message": "Sample created successfully", "sample": sample}

@app.get("/samples/{sample_id}", dependencies=[Depends(get_current_active_user)])
def read_sample(sample_id: int):
    if sample_id not in sample_database:
        raise HTTPException(status_code=404, detail="Sample not found")
    return sample_database[sample_id]

@app.put("/samples/{sample_id}", dependencies=[Depends(get_current_active_user)])
def update_sample(sample_id: int, sample: Sample):
    if sample_id not in sample_database:
        raise HTTPException(status_code=404, detail="Sample not found")
    sample_database[sample_id] = sample
    return {"message": "Sample updated successfully", "sample": sample}

@app.delete("/samples/{sample_id}", dependencies=[Depends(get_current_active_user)])
def delete_sample(sample_id: int):
    if sample_id not in sample_database:
        raise HTTPException(status_code=404, detail="Sample not found")
    del sample_database[sample_id]

# Part 6: Service 3 - User Service

@app.post("/users/", dependencies=[Depends(get_current_active_user)])
def create_user(user: User):
    user.hashed_password = get_password_hash(user.hashed_password)
    user_database[user.username] = user
    return {"message": "User created successfully", "user": user}

@app.get("/users/{username}", dependencies=[Depends(get_current_active_user)])
def read_user(username: str):
    if username not in user_database:
        raise HTTPException(status_code=404, detail="User not found")
    return user_database[username]

@app.put("/users/{username}", dependencies=[Depends(get_current_active_user)])
def update_user(username: str, user: User):
    if username not in user_database:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = get_password_hash(user.hashed_password)
    user_database[username] = user
    return {"message": "User updated successfully", "user": user}

@app.delete("/users/{username}", dependencies=[Depends(get_current_active_user)])
def delete_user(username: str):
    if username not in user_database:
        raise HTTPException(status_code=404, detail="User not found")
    del user_database[username]

# Part 7: Service 4 - Another Service

@app.post("/anotherservice/", dependencies=[Depends(get_current_active_user)])
def create_another(data: Dict[str, str], query_param: str = Query(None, alias="query")):
    return {"data": data, "query_param": query_param}

@app.get("/anotherservice/{id}", dependencies=[Depends(get_current_active_user)])
def read_another(id: int, query_param: str = Query(None)):
    return {"id": id, "query_param": query_param}

@app.put("/anotherservice/{id}", dependencies=[Depends(get_current_active_user)])
def update_another(id: int, data: Dict[str, str], query_param: str = Query(None)):
    return {"id": id, "data": data, "query_param": query_param}

@app.delete("/anotherservice/{id}", dependencies=[Depends(get_current_active_user)])
def delete_another(id: int, query_param: str = Query(None)):
    return {"id": id, "query_param": query_param}

# Part 8: Service 5 - Yet Another Service

@app.post("/yetservice/", dependencies=[Depends(get_current_active_user)])
def create_yet(data: Dict[str, str], query_param: str = Query(None)):
    return {"data": data, "query_param": query_param}

@app.get("/yetservice/{id}", dependencies=[Depends(get_current_active_user)])
def read_yet(id: int, query_param: str = Query(None)):
    return {"id": id, "query_param": query_param}

@app.put("/yetservice/{id}", dependencies=[Depends(get_current_active_user)])
def update_yet(id: int, data: Dict[str, str], query_param: str = Query(None)):
    return {"id": id, "data": data, "query_param": query_param}

@app.delete("/yetservice/{id}", dependencies=[Depends(get_current_active_user)])
def delete_yet(id: int, query_param: str = Query(None)):
    return {"id": id, "query_param": query_param}