from datetime import datetime, timedelta
from typing import Dict

from fastapi import (
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from models.model import ChatSession, Message, RegisterForm, Token, TokenRequest, User

# Secret Key and Algorithm
SECRET_KEY = "skifusdiguyd897289472u3iklrjsdgdsfg"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE_URL = "postgresql+asyncpg://postgres:postgres@localhost/chatdb"
engine = create_async_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine, class_=AsyncSession
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 token scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

Base = declarative_base()

app = FastAPI()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(SessionLocal)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Initialize the database
@app.on_event("startup")
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.post("/")
def main(user: TokenRequest):
    return user


# User Registration
@app.post("/register", response_model=Dict)
async def register_user(form: RegisterForm = Body(...)):
    db = SessionLocal()

    hashed_password = hash_password(form.password)
    user = User(username=form.username, hashed_password=hashed_password)
    db.add(user)
    try:
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Username already exists")

    return {"msg": "User registered successfully"}


# Token Authentication
@app.post("/token", response_model=Token)
async def login(form_data: TokenRequest = Body(...)):
    db = SessionLocal()

    query = await db.execute(
        text("SELECT * FROM users WHERE username = :username"),
        {"username": form_data.username},
    )
    user = query.fetchone()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(data={"sub": user.username})

    return {"access_token": access_token, "token_type": "bearer"}


# Start a New Session
@app.post("/start-session")
async def start_session(
    user: str = Depends(get_current_user), db: AsyncSession = Depends(SessionLocal)
):
    session = ChatSession(user_id=user)
    db.add(session)
    await db.commit()
    return {"session_id": session.id}


# Get Chat History
@app.get("/chat-history/{session_id}")
async def get_chat_history(
    session_id: str,
    user: str = Depends(get_current_user),
    db: AsyncSession = Depends(SessionLocal),
):
    query = await db.execute(
        "SELECT role, content FROM messages WHERE session_id = :session_id",
        {"session_id": session_id},
    )
    messages = query.fetchall()
    return {
        "messages": [{"role": msg.role, "content": msg.content} for msg in messages]
    }


# WebSocket Chat
@app.websocket("/ws/chat/{session_id}")
async def websocket_endpoint(
    websocket: WebSocket, session_id: str, db: AsyncSession = Depends(SessionLocal)
):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            message = Message(session_id=session_id, role="user", content=data)
            db.add(message)

            # Simulate Assistant Reply
            response = f"Assistant: {data}"  # Replace with your AI model logic
            assistant_message = Message(
                session_id=session_id, role="assistant", content=response
            )
            db.add(assistant_message)

            await db.commit()

            # Send Response
            await websocket.send_text(response)
    except WebSocketDisconnect:
        pass
