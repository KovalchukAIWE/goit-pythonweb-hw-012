# tests/test_crud.py
import pytest
from app import crud, schemas
from app.database import SessionLocal

@pytest.fixture
def db_session():
    """
    Фікстура для створення тестової сесії бази даних.
    Використовуйте in-memory SQLite або окрему тестову БД.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_create_user(db_session):
    """
    Тест створення користувача.
    """
    user_data = schemas.UserCreate(
        email="test@example.com",
        full_name="Test User",
        password="secret"
    )
    user = crud.create_user(db_session, user_data)
    assert user.email == "test@example.com"
    assert user.full_name == "Test User"

def test_password_hash_and_verify():
    """
    Тест хешування та перевірки пароля.
    """
    password = "secret"
    hashed = crud.get_password_hash(password)
    assert crud.verify_password(password, hashed)
