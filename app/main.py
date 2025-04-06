# app/main.py
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request, status, Body
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from pydantic import EmailStr
from sqlalchemy.orm import Session
from typing import List
from datetime import timedelta
import os
import time

from app import models, schemas, crud, auth
from app.database import SessionLocal, engine
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv

# Завантаження змінних середовища
load_dotenv()

# Налаштування Cloudinary
cloudinary.config(
  cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
  api_key=os.getenv("CLOUDINARY_API_KEY"),
  api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# Створення таблиць у базі даних
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Contact API",
    description="REST API для зберігання та управління контактами",
    version="1.0.0"
)

# Увімкнення CORS (не забудьте обмежити доступ у production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    """
    Забезпечує сесію бази даних для обробки запитів.

    Yields:
        Session: Сесія бази даних.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Проста in-memory система rate limiting для маршруту /me (5 запитів за 60 секунд)
user_requests = {}
RATE_LIMIT = 5  # максимальна кількість запитів
TIME_WINDOW = 60  # секунд

def rate_limit(request: Request):
    """
    Перевіряє кількість запитів від одного клієнта та генерує помилку, якщо ліміт перевищено.

    Args:
        request (Request): Об'єкт HTTP запиту.

    Raises:
        HTTPException: Якщо кількість запитів перевищує дозволений ліміт.
    """
    client_ip = request.client.host
    current_time = time.time()
    if client_ip not in user_requests:
        user_requests[client_ip] = []
    # Видаляємо застарілі записи запитів
    user_requests[client_ip] = [
        timestamp for timestamp in user_requests[client_ip]
        if current_time - timestamp < TIME_WINDOW
    ]
    if len(user_requests[client_ip]) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests")
    user_requests[client_ip].append(current_time)

# --- Ендпоінти аутентифікації ---

@app.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Реєструє нового користувача.

    Args:
        user (schemas.UserCreate): Дані користувача для реєстрації.
        db (Session): Сесія бази даних.

    Returns:
        schemas.UserOut: Дані зареєстрованого користувача.

    Raises:
        HTTPException: Якщо користувач із заданим email вже існує.
    """
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=409, detail="User with this email already exists")
    new_user = crud.create_user(db, user)
    # Можна додати background task для відправки листа з верифікацією
    return new_user

@app.post("/token", response_model=schemas.Token)
def login(login_data: schemas.Login, db: Session = Depends(get_db)):
    """
    Авторизує користувача та повертає JWT токен доступу.

    Args:
        login_data (schemas.Login): Дані для логіну (email, пароль).
        db (Session): Сесія бази даних.

    Returns:
        dict: Словник з access_token та token_type.

    Raises:
        HTTPException: Якщо email або пароль невірні.
    """
    user = crud.authenticate_user(db, email=login_data.email, password=login_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=crud.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = crud.create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me", response_model=schemas.UserOut)
def read_me(current_user: models.User = Depends(auth.get_current_active_user), request: Request = None, _: None = Depends(rate_limit)):
    """
    Повертає дані поточного авторизованого користувача.

    Args:
        current_user (models.User): Поточний користувач, отриманий через Depends.
        request (Request): HTTP запит (використовується для rate limiting).

    Returns:
        schemas.UserOut: Дані поточного користувача.
    """
    return current_user

@app.post("/me/avatar", response_model=schemas.UserOut)
def update_avatar(file: UploadFile = File(...), current_user: models.User = Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    """
    Оновлює аватар користувача через завантаження файлу до Cloudinary.

    Args:
        file (UploadFile): Файл нового аватара.
        current_user (models.User): Поточний авторизований користувач.
        db (Session): Сесія бази даних.

    Returns:
        schemas.UserOut: Оновлені дані користувача з новим аватаром.
    """
    if current_user.avatar_url == "default_avatar.png" and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Тільки адміністратори можуть змінювати аватар за замовчуванням")
    result = cloudinary.uploader.upload(file.file)
    current_user.avatar_url = result.get("secure_url")
    db.commit()
    db.refresh(current_user)
    return current_user

@app.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    """
    Верифікує електронну пошту користувача на основі наданого токена (тут використовується email як токен).

    Args:
        token (str): Токен для верифікації (email).
        db (Session): Сесія бази даних.

    Returns:
        dict: Повідомлення про успішну верифікацію.

    Raises:
        HTTPException: Якщо користувача з таким email не знайдено.
    """
    user = crud.get_user_by_email(db, email=token)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")
    user.is_verified = True
    db.commit()
    return {"detail": "Email verified successfully"}

# --- Ендпоінти для роботи з контактами (тільки для автентифікованих користувачів) ---

@app.post("/contacts/", response_model=schemas.ContactOut, status_code=status.HTTP_201_CREATED)
def create_contact(contact: schemas.ContactCreate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """
    Створює новий контакт для поточного користувача.

    Args:
        contact (schemas.ContactCreate): Дані нового контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний авторизований користувач.

    Returns:
        schemas.ContactOut: Дані створеного контакту.
    """
    return crud.create_contact(db, contact, current_user.id)

@app.get("/contacts/", response_model=List[schemas.ContactOut])
def read_contacts(
    skip: int = 0,
    limit: int = 100,
    query: str = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """
    Повертає список контактів поточного користувача з можливістю пагінації та пошуку.

    Args:
        skip (int, optional): Кількість контактів для пропуску. За замовчуванням 0.
        limit (int, optional): Максимальна кількість контактів. За замовчуванням 100.
        query (str, optional): Пошуковий запит для фільтрації контактів.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний авторизований користувач.

    Returns:
        List[schemas.ContactOut]: Список контактів.
    """
    if query:
        contacts = crud.search_contacts(db, current_user.id, query)
    else:
        contacts = crud.get_contacts(db, current_user.id, skip=skip, limit=limit)
    return contacts

@app.get("/contacts/{contact_id}", response_model=schemas.ContactOut)
def read_contact(contact_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """
    Повертає дані контакту за його ID.

    Args:
        contact_id (int): Ідентифікатор контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний авторизований користувач.

    Returns:
        schemas.ContactOut: Дані контакту.

    Raises:
        HTTPException: Якщо контакт не знайдено.
    """
    db_contact = crud.get_contact(db, current_user.id, contact_id)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Контакт не знайдено")
    return db_contact

@app.put("/contacts/{contact_id}", response_model=schemas.ContactOut)
def update_contact(contact_id: int, contact: schemas.ContactUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """
    Оновлює дані контакту за заданим ID.

    Args:
        contact_id (int): Ідентифікатор контакту.
        contact (schemas.ContactUpdate): Нові дані для контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний авторизований користувач.

    Returns:
        schemas.ContactOut: Оновлені дані контакту.

    Raises:
        HTTPException: Якщо контакт не знайдено.
    """
    db_contact = crud.update_contact(db, current_user.id, contact_id, contact)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Контакт не знайдено")
    return db_contact


@app.post("/reset-password-request")
def reset_password_request(email: EmailStr, db: Session = Depends(get_db)):
    """
    Генерує JWT токен для скидання пароля та симулює відправку листа.

    :param email: Email користувача, який хоче скинути пароль.
    :param db: Сесія бази даних.
    :return: Повідомлення про генерацію токену.
    :raises HTTPException: Якщо користувача з таким email не існує.
    """
    user = crud.get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    reset_token = crud.create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=15)
    )
    # Тут потрібно інтегрувати відправку листа з reset_token (можна використати Celery або інший background task)
    return {"detail": "Reset token generated", "reset_token": reset_token}


@app.post("/reset-password")
def reset_password(reset_token: str = Body(...), new_password: str = Body(...), db: Session = Depends(get_db)):
    """
    Скидає пароль користувача, використовуючи JWT токен.

    :param reset_token: Токен, отриманий через /reset-password-request.
    :param new_password: Новий пароль.
    :param db: Сесія бази даних.
    :return: Повідомлення про успішну зміну пароля.
    :raises HTTPException: Якщо токен недійсний або користувача не знайдено.
    """
    from jose import JWTError
    try:
        payload = jwt.decode(reset_token, crud.SECRET_KEY, algorithms=[crud.ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid reset token")
    user = crud.get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = crud.get_password_hash(new_password)
    db.commit()
    return {"detail": "Password reset successful"}
@app.delete("/contacts/{contact_id}")
def delete_contact(contact_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """
    Видаляє контакт за його ID.

    Args:
        contact_id (int): Ідентифікатор контакту.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний авторизований користувач.

    Returns:
        dict: Повідомлення про успішне видалення контакту.

    Raises:
        HTTPException: Якщо контакт не знайдено.
    """
    db_contact = crud.delete_contact(db, current_user.id, contact_id)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Контакт не знайдено")
    return {"detail": "Контакт видалено"}

@app.get("/contacts/birthdays/", response_model=List[schemas.ContactOut])
def read_birthdays(days: int = 7, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """
    Повертає список контактів, у яких день народження протягом наступних `days` днів.

    Args:
        days (int, optional): Кількість днів для пошуку днів народження. За замовчуванням 7.
        db (Session): Сесія бази даних.
        current_user (models.User): Поточний авторизований користувач.

    Returns:
        List[schemas.ContactOut]: Список контактів з майбутніми днями народження.
    """
    return crud.get_birthdays(db, current_user.id, days)
