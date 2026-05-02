import pytest
import time
import json
import sys
import os
import logging
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app import app, USERS, ip_attempts, user_lockouts, reset_user_failures

# Configuración de logging que funciona bien con pytest
# Se elimina cualquier configuración previa y se crea un logger específico
logger = logging.getLogger('secureauth_tests')
logger.setLevel(logging.INFO)

# Handler para archivo
file_handler = logging.FileHandler('test_results.log', mode='w')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
file_handler.setFormatter(file_formatter)

# Handler para consola (formato más sencillo)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%H:%M:%S')
console_handler.setFormatter(console_formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Evitar que los mensajes se dupliquen
logger.propagate = False

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def reset_state():
    """Reset global state before each test and log the action"""
    ip_attempts.clear()
    user_lockouts.clear()
    reset_user_failures('admin')
    reset_user_failures('alice')
    reset_user_failures('bob')
    logger.debug("Estado global restablecido")

def get_totp_code(client, username):
    """Helper to get TOTP code for testing"""
    response = client.get(f'/api/demo_totp/{username}')
    if response.status_code == 200:
        return response.get_json()['code']
    return '000000'

# ------------------- TESTS -------------------

class TestRateLimiting:
    def test_rate_limiting_ip(self, client):
        logger.info("=== INICIO: test_rate_limiting_ip ===")
        for i in range(11):
            response = client.post('/login', data={
                'username': 'nonexistent',
                'password': 'wrong',
                'totp': '000000'
            })
            if i < 10:
                assert response.status_code == 200, f"Intento {i+1}: se esperaba 200, obtuvo {response.status_code}"
                logger.info(f"Intento {i+1}/10 fallido (esperado) - status 200")
            else:
                assert response.status_code == 429, f"Intento 11: se esperaba 429 (rate limit), obtuvo {response.status_code}"
                logger.info("Intento 11 correctamente bloqueado por rate limiting (429)")
        logger.info("=== FIN: test_rate_limiting_ip - OK ===")

    def test_rate_limiting_window(self, client):
        logger.info("=== INICIO: test_rate_limiting_window ===")
        for _ in range(10):
            client.post('/login', data={
                'username': 'nonexistent',
                'password': 'wrong',
                'totp': '000000'
            })
        response = client.post('/login', data={
            'username': 'nonexistent',
            'password': 'wrong',
            'totp': '000000'
        })
        assert response.status_code == 429
        logger.info("Límite alcanzado, confirmado 429")

        with patch('app.time.time', return_value=time.time() + 61):
            response2 = client.post('/login', data={
                'username': 'nonexistent',
                'password': 'wrong',
                'totp': '000000'
            })
            assert response2.status_code == 200
            logger.info("Después de 61s, el rate limit se resetea (status 200)")
        logger.info("=== FIN: test_rate_limiting_window - OK ===")

class TestAccountLockout:
    def test_account_lockout_progressive(self, client):
        logger.info("=== test_account_lockout_progressive ===")
        for i in range(5):
            response = client.post('/login', data={
                'username': 'admin',
                'password': 'wrong',
                'totp': '000000'
            })
            assert response.status_code == 200
            logger.info(f"Fallo {i+1}/5 - cuenta aún activa")
        response6 = client.post('/login', data={
            'username': 'admin',
            'password': 'wrong',
            'totp': '000000'
        })
        assert response6.status_code == 403
        logger.info("Sexto fallo ==> cuenta bloqueada (403)")
        logger.info("=== test_account_lockout_progressive OK ===")

    def test_lockout_expires(self, client):
        logger.info("=== test_lockout_expires ===")
        for _ in range(5):
            client.post('/login', data={
                'username': 'admin',
                'password': 'wrong',
                'totp': '000000'
            })
        with patch('app.time.time', return_value=time.time() + 301):
            response = client.post('/login', data={
                'username': 'admin',
                'password': 'wrong',
                'totp': '000000'
            })
            assert response.status_code == 200
            logger.info("Después de 301s, el bloqueo expiró (status 200)")
        logger.info("=== test_lockout_expires OK ===")

class TestMFA:
    def test_login_without_totp_fails(self, client):
        logger.info("=== test_login_without_totp_fails ===")
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'S3cur3P@ss!2025',
            'totp': '000000'
        })
        assert response.status_code == 200
        assert 'Código MFA incorrecto' in response.get_data(as_text=True)
        logger.info("Login con TOTP incorrecto ==> mensaje de error esperado")
        logger.info("=== test_login_without_totp_fails OK ===")

    def test_login_with_correct_totp_succeeds(self, client):
        logger.info("=== test_login_with_correct_totp_succeeds ===")
        totp_code = get_totp_code(client, 'admin')
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'S3cur3P@ss!2025',
            'totp': totp_code
        })
        assert response.status_code == 302
        logger.info(f"TOTP correcto ({totp_code}) ==> redirección al dashboard (302)")
        logger.info("=== test_login_with_correct_totp_succeeds OK ===")

class TestPasswordHashing:
    def test_passwords_are_hashed(self):
        logger.info("=== test_passwords_are_hashed ===")
        assert 'password_hash' in USERS['admin']
        assert isinstance(USERS['admin']['password_hash'], bytes)
        import bcrypt
        assert bcrypt.checkpw('S3cur3P@ss!2025'.encode(), USERS['admin']['password_hash'])
        logger.info("La contraseña almacenada es un hash bcrypt válido")
        logger.info("=== test_passwords_are_hashed OK ===")

class TestAntiEnumeration:
    def test_same_error_message(self, client):
        logger.info("=== test_same_error_message ===")
        resp1 = client.post('/login', data={
            'username': 'nonexistent',
            'password': 'wrong',
            'totp': '000000'
        })
        resp2 = client.post('/login', data={
            'username': 'admin',
            'password': 'wrong',
            'totp': '000000'
        })
        assert 'Usuario o contraseña incorrectos' in resp1.get_data(as_text=True)
        assert 'Usuario o contraseña incorrectos' in resp2.get_data(as_text=True)
        logger.info("Ambos casos (usuario inexistente / contraseña errónea) muestran el mismo mensaje")
        logger.info("=== test_same_error_message OK ===")

class TestSessionFixation:
    def test_session_id_changes_after_login(self, client):
        logger.info("=== test_session_id_changes_after_login ===")
        client.get('/login')
        initial_cookie = client.get_cookie('session')
        totp_code = get_totp_code(client, 'admin')
        client.post('/login', data={
            'username': 'admin',
            'password': 'S3cur3P@ss!2025',
            'totp': totp_code
        })
        final_cookie = client.get_cookie('session')
        assert (initial_cookie is None and final_cookie is not None) or (initial_cookie != final_cookie)
        logger.info(f"Cookie inicial: {initial_cookie}, final: {final_cookie} ==> sesión regenerada")
        logger.info("=== test_session_id_changes_after_login OK ===")

class TestSessionTimeout:
    def test_session_expires(self, client):
        logger.info("=== test_session_expires ===")
        totp_code = get_totp_code(client, 'admin')
        client.post('/login', data={
            'username': 'admin',
            'password': 'S3cur3P@ss!2025',
            'totp': totp_code
        })
        response = client.get('/dashboard')
        assert response.status_code == 200
        logger.info("Sesión activa ==> dashboard accesible")

        with patch('app.time.time', return_value=time.time() + 901):
            response2 = client.get('/dashboard')
            assert response2.status_code == 302
            logger.info("Después de 901s ==> redirigido a login (302)")
        logger.info("=== test_session_expires OK ===")

class TestNoHardcodedSecrets:
    def test_secret_key_generated(self):
        logger.info("=== test_secret_key_generated ===")
        assert app.secret_key is not None
        assert app.secret_key != ''
        logger.info(f"Secret key configurada: {app.secret_key}")
        logger.info("=== test_secret_key_generated OK ===")