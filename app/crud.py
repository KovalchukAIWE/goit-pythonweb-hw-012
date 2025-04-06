# app/crud.py
from sqlalchemy.orm import Session
from . import models, schemas
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt
import os

# Налаштування контексту для хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def get_password_hash(password: str) -> str:
    """
    Хешує пароль користувача.

    Args:
        password (str): Звичайний текст пароля.

    Returns:
        str: Захешований пароль.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Перевіряє відповідність звичайного пароля та захешованого.

    Args:
        plain_password (str): Звичайний текст пароля.
        hashed_password (str): Захешований пароль.

    Returns:
        bool: True, якщо паролі співпадають, інакше False.
    """
    return pwd_context.verify(plain_password, hashed_password)

# --- Робота з користувачами ---

def get_user_by_email(db: Session, email: str):
    """
    Отримує користувача з бази даних за email.

    Args:
        db (Session): Сесія бази даних.
        email (str): Електронна пошта користувача.

    Returns:
        models.User або None: Об'єкт користувача або None, якщо не знайдено.
    """
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    """
    Створює нового користувача та зберігає його в базі даних.

    Args:
        db (Session): Сесія бази даних.
        user (schemas.UserCreate): Дані користувача для створення.

    Returns:
        models.User: Створений об'єкт користувача.
    """
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, email: str, password: str):
    """
    Перевіряє дані користувача для аутентифікації.

    Args:
        db (Session): Сесія бази даних.
        email (str): Електронна пошта користувача.
        password (str): Пароль користувача.

    Returns:
        models.User або None: Об'єкт користувача, якщо аутентифікація пройшла успішно, або None.
    """
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """
    Створює JWT токен доступу.

    Args:
        data (dict): Дані, які будуть закодовані в токені.
        expires_delta (timedelta, optional): Тривалість життя токена.

    Returns:
        str: Закодований JWT токен.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Робота з контактами (зв’язок з користувачем) ---

def get_contacts(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    """
    Повертає список контактів для заданого користувача.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): Ідентифікатор користувача.
        skip (int, optional): Кількість контактів для пропуску.
        limit (int, optional): Максимальна кількість контактів.

    Returns:
        List[models.Contact]: Список контактів.
    """
    return db.query(models.Contact).filter(models.Contact.user_id == user_id).offset(skip).limit(limit).all()

def search_contacts(db: Session, user_id: int, query: str):
    """
    Шукає контакти користувача за частковим збігом за ім'ям, прізвищем або email.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): Ідентифікатор користувача.
        query (str): Пошуковий запит.

    Returns:
        List[models.Contact]: Список контактів, що відповідають запиту.
    """
    return db.query(models.Contact).filter(models.Contact.user_id == user_id).filter(
        (models.Contact.first_name.ilike(f"%{query}%")) |
        (models.Contact.last_name.ilike(f"%{query}%")) |
        (models.Contact.email.ilike(f"%{query}%"))
    ).all()

def get_contact(db: Session, user_id: int, contact_id: int):
    """
    Повертає контакт за його ID для заданого користувача.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): Ідентифікатор користувача.
        contact_id (int): Ідентифікатор контакту.

    Returns:
        models.Contact або None: Об'єкт контакту або None, якщо не знайдено.
    """
    return db.query(models.Contact).filter(models.Contact.user_id == user_id, models.Contact.id == contact_id).first()

def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int):
    """
    Створює новий контакт для заданого користувача.

    Args:
        db (Session): Сесія бази даних.
        contact (schemas.ContactCreate): Дані нового контакту.
        user_id (int): Ідентифікатор користувача.

    Returns:
        models.Contact: Створений контакт.
    """
    db_contact = models.Contact(**contact.dict(), user_id=user_id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def update_contact(db: Session, user_id: int, contact_id: int, contact: schemas.ContactUpdate):
    """
    Оновлює дані контакту.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): Ідентифікатор користувача.
        contact_id (int): Ідентифікатор контакту.
        contact (schemas.ContactUpdate): Нові дані контакту.

    Returns:
        models.Contact або None: Оновлений контакт або None, якщо контакт не знайдено.
    """
    db_contact = get_contact(db, user_id, contact_id)
    if not db_contact:
        return None
    for key, value in contact.dict(exclude_unset=True).items():
        setattr(db_contact, key, value)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, user_id: int, contact_id: int):
    """
    Видаляє контакт.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): Ідентифікатор користувача.
        contact_id (int): Ідентифікатор контакту.

    Returns:
        models.Contact або None: Видалений контакт або None, якщо контакт не знайдено.
    """
    db_contact = get_contact(db, user_id, contact_id)
    if not db_contact:
        return None
    db.delete(db_contact)
    db.commit()
    return db_contact

def get_birthdays(db: Session, user_id: int, days: int):
    """
    Повертає список контактів з днями народження, що настануть протягом заданої кількості днів.

    Args:
        db (Session): Сесія бази даних.
        user_id (int): Ідентифікатор користувача.
        days (int): Кількість днів для пошуку днів народження.

    Returns:
        List[models.Contact]: Список контактів з майбутніми днями народження.
    """
    today = datetime.today()
    future_date = today + timedelta(days=days)
    return db.query(models.Contact).filter(
        models.Contact.user_id == user_id,
        models.Contact.birthday >= today,
        models.Contact.birthday <= future_date
    ).all()
