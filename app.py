"""
OWASP A07:2025 - Authentication Failures Demo
Secure Login System con protecciones contra:
  - Brute Force / Ataques de diccionario
  - Credential Stuffing
  - Session Fixation
  - Password spraying
  - Enumeración de usuarios
"""

import os
import secrets
import time
import json
import hashlib
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps

import bcrypt
import pyotp
from flask import (Flask, render_template, request, session,
                   redirect, url_for, jsonify, g)

# CONFIG
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)          # CWE-259: NO hardcoded secrets
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,               # CWE-384: Session fixation
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,                # True en prod (HTTPS)
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),  # CWE-613: Session timeout
)

# LOGGING SETUP
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('auth_events.log')
    ]
)
logger = logging.getLogger('auth')

# IN-MEMORY STORAGE (simula DB)
# Passwords hasheados con bcrypt (CWE-521, A04 Cryptographic Failures)
USERS = {}

def create_user(username, password, totp_secret=None):
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    USERS[username] = {
        'password_hash': hashed,
        'totp_secret': totp_secret or pyotp.random_base32(),
        'created_at': datetime.utcnow().isoformat(),
        'failed_attempts': 0,
        'locked_until': None,
        'last_login': None,
        'sessions': set(),
    }

# Usuarios demo
create_user('admin', 'S3cur3P@ss!2025')
create_user('alice', 'AliceRocks#99')
create_user('bob',   'B0bIsH3re$2025')

# RATE LIMITING (en memoria, para demo)
# En producción usa Redis + flask-limiter
ip_attempts = defaultdict(list)        # ip -> [timestamps]
user_lockouts = {}                     # username -> locked_until timestamp

MAX_ATTEMPTS_PER_IP  = 10             # por ventana de tiempo
MAX_ATTEMPTS_PER_USER = 3             # antes de lockout
WINDOW_SECONDS       = 60             # ventana de 1 minuto
LOCKOUT_SECONDS      = 300            # 5 minutos de lockout

# Contraseñas conocidas (top lista OWASP / rockyou sample)
COMMON_PASSWORDS = {
    'password', 'password1', '123456', '12345678', 'admin', 'admin123',
    'letmein', 'welcome', 'monkey', 'dragon', 'master', 'sunshine',
    'princess', 'password123', 'iloveyou', 'football', 'shadow',
    'superman', 'michael', 'qwerty', 'abc123', '111111', 'mustang',
    '1234567', 'baseball', 'charlie', 'donald', 'batman', 'passw0rd',
    'winter2024', 'winter2025', 'spring2025', 'summer2025',
}

# HELPERS

def get_client_ip():
    """Obtiene IP real incluso detrás de proxy."""
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()


def is_ip_rate_limited(ip: str) -> tuple[bool, int]:
    """Ventana deslizante para limitar intentos por IP."""
    now = time.time()
    window_start = now - WINDOW_SECONDS
    # Limpiar intentos viejos
    ip_attempts[ip] = [t for t in ip_attempts[ip] if t > window_start]
    count = len(ip_attempts[ip])
    if count >= MAX_ATTEMPTS_PER_IP:
        wait = int(WINDOW_SECONDS - (now - ip_attempts[ip][0])) + 1
        return True, wait
    return False, 0


def record_ip_attempt(ip: str):
    ip_attempts[ip].append(time.time())


def is_user_locked(username: str) -> tuple[bool, int]:
    """Verifica lockout progresivo por usuario."""
    locked_until = user_lockouts.get(username)
    if locked_until and time.time() < locked_until:
        wait = int(locked_until - time.time()) + 1
        return True, wait
    return False, 0


def record_user_failure(username: str):
    """Incrementa contador de fallos y aplica lockout exponencial."""
    if username not in USERS:
        return
    user = USERS[username]
    user['failed_attempts'] += 1
    # Lockout progresivo: 5, 25, 125... segundos (exponencial)
    if user['failed_attempts'] >= MAX_ATTEMPTS_PER_USER:
        factor = min(user['failed_attempts'] - MAX_ATTEMPTS_PER_USER + 1, 5)
        lockout = LOCKOUT_SECONDS * (5 ** (factor - 1))
        user_lockouts[username] = time.time() + lockout
        logger.warning(f"LOCKOUT usuario='{username}' duración={lockout}s intentos={user['failed_attempts']}")


def reset_user_failures(username: str):
    if username in USERS:
        USERS[username]['failed_attempts'] = 0
    if username in user_lockouts:
        del user_lockouts[username]


def generic_auth_error():
    """SIEMPRE retorna el mismo mensaje - evita enumeración de usuarios (CWE-287)."""
    return "Usuario o contraseña incorrectos."


def generate_session_id():
    """Token de alta entropía para sesión - CWE-384 Session Fixation."""
    return secrets.token_urlsafe(32)


def log_event(event_type, username=None, ip=None, extra=None):
    """Registro estructurado de eventos de autenticación."""
    ip = ip or get_client_ip()
    entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'event': event_type,
        'ip': ip,
        'username': username or 'unknown',
        'user_agent': request.user_agent.string[:100],
    }
    if extra:
        entry.update(extra)
    logger.info(json.dumps(entry))
    # Guardar en memoria para el dashboard
    EVENTS.append(entry)
    if len(EVENTS) > 200:
        EVENTS.pop(0)


EVENTS = []   # log circular en memoria para visualización


# RUTAS

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    warn  = None

    if request.method == 'POST':
        ip       = get_client_ip()
        username = request.form.get('username', '').strip()[:64]
        password = request.form.get('password', '')[:128]
        totp_code = request.form.get('totp', '').strip()

        # 1. Rate limiting por IP
        limited, wait = is_ip_rate_limited(ip)
        if limited:
            log_event('RATE_LIMIT_IP', ip=ip, extra={'wait': wait})
            error = f"Demasiados intentos desde tu IP. Espera {wait}s."
            return render_template('login.html', error=error), 429

        record_ip_attempt(ip)

        # 2. Lockout por usuario
        locked, wait = is_user_locked(username)
        if locked:
            log_event('LOCKOUT_BLOCKED', username=username, ip=ip)
            # Mismo mensaje genérico (anti-enumeración)
            error = generic_auth_error()
            return render_template('login.html', error=error, locked=True, wait=wait), 403

        # 3. Validar credenciales (timing-safe)
        user = USERS.get(username)

        # Siempre ejecutar bcrypt aunque el usuario no exista (anti-timing)
        dummy_hash = bcrypt.hashpw(b'dummy', bcrypt.gensalt())
        check_hash = user['password_hash'] if user else dummy_hash

        try:
            valid_pw = bcrypt.checkpw(password.encode(), check_hash)
        except Exception:
            valid_pw = False

        if not user or not valid_pw:
            record_user_failure(username)
            log_event('LOGIN_FAILURE', username=username, ip=ip,
                      extra={'reason': 'bad_credentials'})
            error = generic_auth_error()
            # Pequeño delay aleatorio anti-timing (100-300ms)
            time.sleep(secrets.randbelow(200) / 1000 + 0.1)
            return render_template('login.html', error=error)

        # 4. Verificar TOTP (MFA) - CWE-308
        totp = pyotp.TOTP(user['totp_secret'])
        if not totp.verify(totp_code, valid_window=1):
            record_user_failure(username)
            log_event('LOGIN_FAILURE', username=username, ip=ip,
                      extra={'reason': 'bad_totp'})
            error = "Código MFA incorrecto."
            return render_template('login.html', error=error, show_totp=True,
                                   username_hint=username)

        # 5. Login exitoso
        reset_user_failures(username)

        # Session Fixation: regenerar ID (CWE-384)
        session.clear()
        session['user']       = username
        session['session_id'] = generate_session_id()
        session['login_at']   = datetime.utcnow().isoformat()
        session['ip']         = ip
        session.permanent     = True

        USERS[username]['last_login'] = datetime.utcnow().isoformat()

        log_event('LOGIN_SUCCESS', username=username, ip=ip)
        return redirect(url_for('dashboard'))

    return render_template('login.html', error=error, warn=warn)


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    # Verificar que la sesión no expiró (ya lo maneja Flask con PERMANENT_SESSION_LIFETIME)
    username = session['user']
    user = USERS.get(username, {})
    return render_template('dashboard.html',
                           username=username,
                           last_login=user.get('last_login'),
                           totp_secret=user.get('totp_secret'),
                           events=list(reversed(EVENTS[-50:])))


@app.route('/logout', methods=['POST'])
def logout():
    """Invalidar sesión correctamente - CWE-613."""
    username = session.get('user')
    if username:
        log_event('LOGOUT', username=username)
    session.clear()
    return redirect(url_for('login'))


# API: Estado del sistema para el panel de monitoreo

@app.route('/api/status')
def api_status():
    """Devuelve métricas en tiempo real para el dashboard de seguridad."""
    now = time.time()
    window = now - WINDOW_SECONDS

    # IPs activas con intentos
    active_ips = {
        ip: [t for t in attempts if t > window]
        for ip, attempts in ip_attempts.items()
    }
    active_ips = {ip: ts for ip, ts in active_ips.items() if ts}

    # Usuarios bloqueados activos
    active_locks = {
        u: int(t - now)
        for u, t in user_lockouts.items()
        if t > now
    }

    recent = EVENTS[-20:]
    failures = sum(1 for e in recent if 'FAILURE' in e.get('event',''))
    successes = sum(1 for e in recent if 'SUCCESS' in e.get('event',''))

    return jsonify({
        'active_ips': {ip: len(ts) for ip, ts in active_ips.items()},
        'locked_users': active_locks,
        'total_events': len(EVENTS),
        'recent_failures': failures,
        'recent_successes': successes,
        'events': list(reversed(EVENTS[-15:])),
    })


@app.route('/api/totp_qr/<username>')
def totp_qr(username):
    """Genera URI TOTP para configurar en Google Authenticator."""
    if 'user' not in session or session['user'] != username:
        return jsonify({'error': 'unauthorized'}), 401
    user = USERS.get(username)
    if not user:
        return jsonify({'error': 'not found'}), 404
    totp = pyotp.TOTP(user['totp_secret'])
    uri  = totp.provisioning_uri(name=username, issuer_name='OWASP SecureLogin')
    return jsonify({'uri': uri, 'secret': user['totp_secret']})


# ENDPOINT DE PRUEBA: genera código TOTP válido (solo para demo)
@app.route('/api/demo_totp/<username>')
def demo_totp(username):
    """⚠️  Solo para demostración. Nunca en producción."""
    user = USERS.get(username)
    if not user:
        return jsonify({'error': 'not found'}), 404
    totp = pyotp.TOTP(user['totp_secret'])
    return jsonify({
        'code': totp.now(),
        'expires_in': 30 - (int(time.time()) % 30),
        'warning': 'DEMO ONLY - Remove in production'
    })


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  OWASP A07:2025 - Secure Login Demo")
    print("="*60)
    print("  URL:         http://localhost:5000")
    print("  TOTP demo:   GET /api/demo_totp/<username>")
    print("  Status API:  GET /api/status")
    print("\n  Usuarios: admin | alice | bob")
    print("  Passwords: ver app.py líneas create_user()")
    print("="*60 + "\n")
    app.run(debug=True, port=5000)
