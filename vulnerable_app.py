"""
⚠️ VULNERABLE APP - SOLO PARA FINES ACADÉMICOS ⚠️
Esta aplicación demuestra fallas comunes de seguridad (OWASP A07:2025).
NO USAR EN PRODUCCIÓN.
"""

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import hashlib
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "secret_key_fija_muy_debil"  # CWE-259: Hardcoded secret

# Configuración insegura
app.config.update(
    SESSION_COOKIE_HTTPONLY=False,  # Vulnerable a XSS/Session Hijacking
    PERMANENT_SESSION_LIFETIME=timedelta(days=365), # Sesiones que nunca expiran
)

# DB SIMULADA - Contraseñas en TEXTO PLANO (CWE-257)
USERS = {
    'admin': 'S3cur3P@ss!2025',
    'alice': 'AliceRocks#99',
    'bob':   'B0bIsH3re$2025'
}

@app.route('/')
def index():
    if 'user' in session:
        return f"Bienvenido {session['user']}! <a href='/logout'>Cerrar sesión</a>"
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # VULNERABILIDAD 1: Enumeración de usuarios (Mensajes descriptivos)
        if username not in USERS:
            error = f"El usuario '{username}' no existe en nuestra base de datos."
        else:
            # VULNERABILIDAD 2: Sin Rate Limiting ni Lockout
            # Se puede atacar por fuerza bruta infinitamente
            if USERS[username] == password:
                session['user'] = username
                return redirect(url_for('dashboard'))
            else:
                error = f"Contraseña incorrecta para el usuario {username}."

    # Usamos el mismo template pero las variables serán distintas (sin MFA)
    return render_template('login.html', error=error, is_vulnerable=True)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', 
                           username=session['user'], 
                           is_vulnerable=True)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


# API para demostrar que no hay protecciones
@app.route('/api/debug_users')
def debug_users():
    return jsonify(USERS)

if __name__ == '__main__':
    print("\n" + "!"*60)
    print("  MODO VULNERABLE ACTIVADO - http://localhost:5001")
    print("  Usa esto para mostrar por qué la otra versión es mejor.")
    print("!"*60 + "\n")
    app.run(debug=True, port=5001)
