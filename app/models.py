# app/models.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    """
    Модель користувача.

    Attributes:
        id (int): Унікальний ідентифікатор користувача.
        email (str): Електронна пошта користувача.
        full_name (str): Повне ім'я користувача.
        hashed_password (str): Захешований пароль користувача.
        is_active (bool): Статус активності користувача.
        is_verified (bool): Показник верифікації користувача.
        avatar_url (str, optional): URL аватара користувача.
        contacts (List[Contact]): Список контактів, пов’язаних із користувачем.
    """
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    avatar_url = Column(String, nullable=True)

    contacts = relationship("Contact", back_populates="owner")

class Contact(Base):
    """
    Модель контакту.

    Attributes:
        id (int): Унікальний ідентифікатор контакту.
        first_name (str): Ім'я контакту.
        last_name (str): Прізвище контакту.
        email (str): Електронна пошта контакту.
        phone (str, optional): Номер телефону контакту.
        birthday (datetime, optional): Дата народження контакту.
        user_id (int): Ідентифікатор користувача, якому належить контакт.
        owner (User): Об'єкт користувача, що є власником контакту.
    """
    __tablename__ = "contacts"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True)
    phone = Column(String, nullable=True)
    birthday = Column(DateTime, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    role = Column(String, default="user", nullable=False)

    owner = relationship("User", back_populates="contacts")
