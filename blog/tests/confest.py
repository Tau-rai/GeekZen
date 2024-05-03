import os
import pytest
from flaskr import create_app
from flaskr.db import get_db

@pytest.fixture
def app():
    db_config = {
        'host': 'localhost',
        'user': 'Tau',
        'password': 'Changamire#97',
        'database': 'test_db',
    }

    app = create_app({
        'TESTING': True,
        'DATABASE': db_config,
    })

    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        with open(os.path.join(os.path.dirname(__file__), 'data.sql'), 'rb') as f:
            sql_commands = f.read().decode('utf8').split(';')
            for command in sql_commands:
                if command.strip() != '':
                    cursor.execute(command)
        db.commit()
        cursor.close()

    yield app

    with app.app_context():
        db = get_db()
        db.cursor().execute('DROP DATABASE IF EXISTS test_db;')
        db.commit()
        cursor.close()

class AuthActions(object):
    def __init__(self, client):
        self._client = client

    def login(self, username='test', password='test'):
        return self._client.post(
            '/auth/login',
            data={'username': username, 'password': password}
        )

    def logout(self):
        return self._client.get('/auth/logout')


@pytest.fixture
def auth(client):
    return AuthActions(client)


