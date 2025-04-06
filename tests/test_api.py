# tests/test_api.py
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_register_and_login():
    """
    Тест реєстрації та логіну користувача.
    """
    # Регістрація користувача
    register_response = client.post("/register", json={
        "email": "api_test@example.com",
        "full_name": "API Tester",
        "password": "secret"
    })
    assert register_response.status_code == 201

    # Логін користувача
    login_response = client.post("/token", json={
        "email": "api_test@example.com",
        "password": "secret"
    })
    assert login_response.status_code == 200
    token = login_response.json().get("access_token")
    assert token is not None

def test_rate_limit_on_me():
    """
    Тест перевірки rate limiting для ендпоінту /me.
    """
    # Використовуємо раніше зареєстрованого користувача
    login_response = client.post("/token", json={
        "email": "api_test@example.com",
        "password": "secret"
    })
    token = login_response.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(5):
        response = client.get("/me", headers=headers)
        assert response.status_code == 200
    # 6-й запит повинен повернути 429 Too Many Requests
    response = client.get("/me", headers=headers)
    assert response.status_code == 429
