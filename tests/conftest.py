"""Shared MySQL fixtures for P2 integration tests.

Set TEST_DB_NAME to an already-created, dedicated database whose name starts
with ``test_``. The fixture refuses to use application databases.
"""
import os
import uuid

import pytest


@pytest.fixture(scope="session")
def mysql_test_db():
    database_name = os.environ.get("TEST_DB_NAME", "")
    if not database_name:
        pytest.skip("TEST_DB_NAME is unset; isolated MySQL integration tests not run")
    if not database_name.startswith("test_"):
        pytest.fail("TEST_DB_NAME must name a dedicated database starting with 'test_'")

    import mysql.connector
    import database as database_module
    import auth_login
    import auth_register
    import auth_mfa

    config = {**database_module.DB_CONFIG, "database": database_name}

    def connect_test_db():
        return mysql.connector.connect(**config)

    # All modules use the same MySQL test database. No SQLite or silent mocks.
    database_module.get_connection = connect_test_db
    auth_login.get_connection = connect_test_db
    auth_register.get_connection = connect_test_db
    auth_mfa.get_connection = connect_test_db
    database_module._pool = None
    database_module.init_db()
    return connect_test_db


@pytest.fixture
def p2_user(mysql_test_db):
    import auth_register

    username = f"p2_{uuid.uuid4().hex[:16]}"
    email = f"{username}@example.test"
    password = "Correct-P2-Test-Password-42"
    with mysql_test_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
            (username, email, auth_register.hash_password(password)),
        )
        user_id = cursor.lastrowid
        conn.commit()

    data = {"id": user_id, "username": username, "email": email, "password": password}
    yield data

    with mysql_test_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        cursor.execute("DELETE FROM login_attempts WHERE identifier LIKE %s", (f"{username}%",))
        conn.commit()
