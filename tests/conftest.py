# tests/conftest.py
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["DATABASE_URL"] = "postgresql+psycopg2://postgres:12345@localhost:5432/postgres"
