# app/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

# Завантаження змінних середовища
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:12345@db:5432/postgres")

# Створення рушія бази даних
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Фабрика сесій для роботи з базою даних
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Базовий клас для моделей SQLAlchemy
Base = declarative_base()
