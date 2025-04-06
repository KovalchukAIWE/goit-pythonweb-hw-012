# app/auth.py
from datetime import timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from . import crud, schemas, models
from .database import SessionLocal
import os
import redis
import json

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))

def get_db():
    """
    Забезпечує сесію бази даних для аутентифікації.

    Yields:
        Session: Сесія бази даних.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Отримує поточного користувача за допомогою JWT токена.

    Args:
        token (str): JWT токен, отриманий через OAuth2PasswordBearer.
        db (Session): Сесія бази даних.

    Returns:
        models.User: Поточний користувач.

    Raises:
        HTTPException: Якщо токен недійсний або користувача не знайдено.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    cache_key = f"user:{email}"
    cached_user = redis_client.get(cache_key)
    if cached_user:
        # Повертаємо дані з кешу (у форматі JSON, який відповідає схемі UserOut)
        return json.loads(cached_user)

    user = crud.get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception

    user_dict = {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "is_verified": user.is_verified,
        "avatar_url": user.avatar_url,
        "role": getattr(user, "role", "user")
    }
    # Зберігаємо в кеш на 5 хвилин
    redis_client.setex(cache_key, timedelta(minutes=5), json.dumps(user_dict))
    return user_dict

def get_current_active_user(current_user: models.User = Depends(get_current_user)):
    """
    Перевіряє, чи активний поточний користувач.

    Args:
        current_user (models.User): Поточний користувач, отриманий через get_current_user.

    Returns:
        models.User: Поточний активний користувач.

    Raises:
        HTTPException: Якщо користувач неактивний.
    """
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
