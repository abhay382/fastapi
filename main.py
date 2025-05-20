import os
import logging
from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer, String, Boolean, DateTime, func, ForeignKey
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing_extensions import Optional
import smtplib
from email.mime.text import MIMEText
import secrets
import aiomysql
from sqlalchemy.sql import select
from urllib.parse import quote_plus

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    logger.warning("python-dotenv not installed. Using default environment variables.")

# Configuration
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "Abhay@9672")
DATABASE_URL = f"mysql+aiomysql://root:{quote_plus(MYSQL_PASSWORD)}@localhost:3306/jay"
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
EMAIL_SENDER = os.getenv("SMTP_USERNAME", "your_email@gmail.com")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "your_email@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "your_app_password")

# FastAPI app
app = FastAPI()

# SQLAlchemy setup
class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(150))
    email = Column(String(255), unique=True, index=True)
    password = Column(String(100))
    is_active = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True, default=None)
    updated_at = Column(DateTime, nullable=True, default=None, onupdate=datetime.utcnow)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

class Token(Base):
    __tablename__ = 'tokens'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    token = Column(String(255), unique=True)
    type = Column(String(50))
    expires_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())

try:
    engine = create_async_engine(DATABASE_URL, echo=True)
    AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
except Exception as e:
    logger.error(f"Failed/**\n * @file main.py\n * @brief Main FastAPI application file for user authentication and management.\n * @details This file contains the FastAPI application setup, database models, endpoints, and utility functions for user registration, authentication, email verification, password management, and profile updates.\n * @version 1.0.0\n * @date 2025-05-19\n * @author Grok, xAI\n * @note Requires Python 3.9+, MySQL, and specific dependencies listed in requirements.txt.\n */\n\nto create database engine: {str(e)}")
    raise

# Dependency to get DB session
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

# Utility functions
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
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

#async def get_user_by_email(db: AsyncSession, email: str):
  #  return await db.execute(
  #      select(User).filter(User.email == email)
   # ).scalar_one_or_none()
async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(User).filter(User.email == email))
    return result.scalar_one_or_none()

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = await get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user

async def send_email(to_email: str, subject: str, body: str):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = to_email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

async def send_verification_email(user: User, background_tasks: BackgroundTasks, db: AsyncSession):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=24)
    db_token = Token(
        user_id=user.id,
        token=token,
        type="verification",
        expires_at=expires_at
    )
    db.add(db_token)
    await db.commit()
    verification_url = f"http://localhost:8000/verify-email?token={token}"
    body = f"Please verify your email by clicking this link: {verification_url}"
    background_tasks.add_task(send_email, user.email, "Verify Your Email", body)
    return token

async def send_password_reset_email(user: User, background_tasks: BackgroundTasks):
    token = create_access_token({"sub": user.email}, expires_delta=timedelta(hours=1))
    reset_url = f"http://localhost:8000/reset-password?token={token}"
    body = f"Reset your password by clicking this link: {reset_url}"
    background_tasks.add_task(send_email, user.email, "Password Reset Request", body)
    return token

# Endpoints
@app.post("/register", response_model=TokenResponse)
async def register(user: UserCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(
        name=user.name,
        email=user.email,
        password=hashed_password,
        is_active=False
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    await send_verification_email(new_user, background_tasks, db)
    access_token = create_access_token(
        data={"sub": new_user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/verify-email")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    db_token = await db.execute(
        select(Token).filter(Token.token == token, Token.type == "verification")
    ).scalar_one_or_none()
    if not db_token or db_token.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = await db.execute(
        select(User).filter(User.id == db_token.user_id, User.is_active == False)
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="User already verified or not found")
    user.is_active = True
    user.verified_at = datetime.utcnow()
    await db.delete(db_token)
    await db.commit()
    return {"message": "Email verified successfully"}

@app.post("/token", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Please verify your email first")
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/change-password")
async def change_password(
        password_data: PasswordChange,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
    ):
    if not verify_password(password_data.old_password, current_user.password):
        raise HTTPException(status_code=400, detail="Incorrect old password")
    current_user.password = get_password_hash(password_data.new_password)
    await db.commit()
    return {"message": "Password changed successfully"}

@app.post("/forgot-password")
async def forgot_password(
        reset_request: PasswordResetRequest,
        background_tasks: BackgroundTasks,
        db: AsyncSession = Depends(get_db)
    ):
    user = await get_user_by_email(db, reset_request.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await send_password_reset_email(user, background_tasks)
    return {"message": "Password reset email sent"}

@app.post("/reset-password")
async def reset_password(
        reset_data: PasswordReset,
        db: AsyncSession = Depends(get_db)
    ):
    try:
        payload = jwt.decode(reset_data.token, JWT_SECRET, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = await get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.password = get_password_hash(reset_data.new_password)
    await db.commit()
    return {"message": "Password reset successfully"}

@app.put("/update-profile")
async def update_profile(
        user_update: UserUpdate,
        background_tasks: BackgroundTasks,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)
    ):
    if user_update.name:
        current_user.name = user_update.name
    if user_update.email:
        existing_user = await get_user_by_email(db, user_update.email)
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(status_code=400, detail="Email already in use")
        current_user.email = user_update.email
        current_user.is_active = False
        await send_verification_email(current_user, background_tasks, db)
    await db.commit()
    return {"message": "Profile updated successfully"}

# Database initialization
@app.on_event("startup")
async def startup():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)