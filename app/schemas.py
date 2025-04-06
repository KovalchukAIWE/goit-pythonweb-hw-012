# app/schemas.py
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

# --- Схеми для контактів ---

class ContactBase(BaseModel):
    """
    Базова схема для контакту.

    Attributes:
        first_name (str): Ім'я контакту.
        last_name (str): Прізвище контакту.
        email (EmailStr): Електронна пошта контакту.
        phone (Optional[str]): Номер телефону контакту.
        birthday (Optional[datetime]): Дата народження контакту.
    """
    first_name: str
    last_name: str
    email: EmailStr
    phone: Optional[str] = None
    birthday: Optional[datetime] = None

class ContactCreate(ContactBase):
    """
    Схема для створення нового контакту.
    """
    pass

class ContactUpdate(ContactBase):
    """
    Схема для оновлення існуючого контакту.
    """
    pass

class ContactOut(ContactBase):
    """
    Схема для виводу даних контакту.

    Attributes:
        id (int): Унікальний ідентифікатор контакту.
    """
    id: int

    class Config:
        orm_mode = True

# --- Схеми для користувачів ---

class UserBase(BaseModel):
    """
    Базова схема для користувача.

    Attributes:
        email (EmailStr): Електронна пошта користувача.
        full_name (str): Повне ім'я користувача.
    """
    email: EmailStr
    full_name: str
    role: Optional[str] = "user"

class UserCreate(UserBase):
    """
    Схема для реєстрації користувача.

    Attributes:
        password (str): Пароль користувача.
    """
    password: str

class UserOut(UserBase):
    """
    Схема для виводу даних користувача.

    Attributes:
        id (int): Унікальний ідентифікатор користувача.
        is_active (bool): Статус активності користувача.
        is_verified (bool): Показник верифікації користувача.
        avatar_url (Optional[str]): URL аватара користувача.
    """
    id: int
    is_active: bool
    is_verified: bool
    avatar_url: Optional[str] = None

    class Config:
        orm_mode = True

# --- Схеми для аутентифікації ---

class Login(BaseModel):
    """
    Схема для логіну користувача.

    Attributes:
        email (EmailStr): Електронна пошта користувача.
        password (str): Пароль користувача.
    """
    email: EmailStr
    password: str

class Token(BaseModel):
    """
    Схема для передачі JWT токена.

    Attributes:
        access_token (str): JWT токен доступу.
        token_type (str): Тип токена.
    """
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """
    Схема для зберігання даних токена.

    Attributes:
        email (Optional[str]): Електронна пошта користувача, отримана з токена.
    """
    email: Optional[str] = None
