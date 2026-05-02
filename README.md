## SecureAuth - Pruebas de seguridad automatizadas (pytest)

Este documento detalla la suite de pruebas desarrollada para validar los mecanismos de seguridad implementados en la aplicación de autenticación **SecureAuth**, alineada con OWASP A07:2025 (Authentication Failures). Las pruebas cubren aspectos críticos como rate limiting, bloqueo de cuentas, MFA (TOTP), hashing de contraseñas, anti-enumeración, protección contra session fixation y timeouts de sesión.

## Estructura del código de pruebas

El archivo de pruebas (`test_auth.py`) utiliza `pytest` como framework de testing y `Flask.test_client` para simular peticiones HTTP sin necesidad de levantar el servidor.

## Configuración y logging

```python
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | TEST | %(message)s',
    handlers=[
        logging.FileHandler('test_results.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('test')
```

- Cada prueba genera entradas de log que se muestran en consola y se guardan en `test_results.log`.
- El formato incluye timestamp, el nivel (`TEST`) y el mensaje, lo que permite auditar la ejecución.

### Fixtures principales

| Fixture | Propósito |
|---------|-----------|
| `client` | Proporciona un cliente de pruebas de Flask (test client) con configuración `TESTING=True`. |
| `reset_state` (autouse) | Limpia el estado global (`ip_attempts`, `user_lockouts` y contadores de fallos de usuarios) **antes de cada prueba**, asegurando aislamiento. |

### Helper: `get_totp_code`

```python
def get_totp_code(client, username):
    response = client.get(f'/api/demo_totp/{username}')
    return response.get_json()['code'] if response.status_code == 200 else '000000'
```

Obtiene dinámicamente el código TOTP válido para el usuario, emulando el flujo real de un autenticador.

## Grupos de pruebas y su implementación

### 1. Rate limiting (IP)

**Objetivo**: Verificar que tras `MAX_ATTEMPTS_PER_IP` (10) intentos fallidos, la IP quede bloqueada durante una ventana de tiempo.

#### Pruebas:

- `test_rate_limiting_ip`: Realiza 11 peticiones de login fallidas. Las primeras 10 deben devolver `200` (página de login con error), la undécima debe ser `429` (Too Many Requests).
- `test_rate_limiting_window`: Llena el límite de intentos y luego simula el avance del tiempo con `patch('app.time.time')` para superar la ventana (60 segundos). Tras el avance, la IP ya no está limitada y la petición devuelve `200`.

### 2. Account lockout progresivo

**Objetivo**: Tras 3 intentos fallidos con el mismo usuario, la cuenta se bloquea temporalmente.

- `test_account_lockout_progressive`: 3 fallos → respuesta `200`; el cuarto fallo → `403` (forbidden por lockout).
- `test_lockout_expires`: Se bloquea la cuenta y luego se simula un avance de 301 segundos (tiempo de bloqueo típico). Tras ese tiempo, la cuenta vuelve a estar disponible (respuesta `200`).

### 3. MFA (TOTP)

**Objetivo**: Obligar al segundo factor de autenticación.

- `test_login_without_totp_fails`: Usa la contraseña correcta pero TOTP incorrecto (`000000`). Debe devolver `200` con el mensaje `"Código MFA incorrecto"`.
- `test_login_with_correct_totp_succeeds`: Obtiene el TOTP real mediante `get_totp_code` y autentica correctamente, obteniendo una redirección (`302`) al dashboard.

### 4. Password hashing

**Objetivo**: Verificar que las contraseñas no se almacenan en texto plano sino como hash bcrypt.

- `test_passwords_are_hashed`: Comprueba que el diccionario `USERS['admin']` contiene una clave `password_hash` de tipo `bytes` y que usando `bcrypt.checkpw` se puede verificar la contraseña real.

### 5. Anti-enumeración (CWE-287)

**Objetivo**: El mensaje de error debe ser idéntico tanto si el usuario no existe como si la contraseña es incorrecta.

- `test_same_error_message`: Se realizan dos peticiones: una con usuario inexistente, otra con usuario existente pero contraseña errónea. Ambas respuestas contienen exactamente el texto `"Usuario o contraseña incorrectos"`.

### 6. Session Fixation (CWE-384)

**Objetivo**: Después de un login exitoso, el ID de sesión debe regenerarse para evitar fijación de sesión.

- `test_session_id_changes_after_login`: Toma la cookie de sesión inicial (antes de autenticarse), realiza un login correcto y compara con la nueva cookie. Se verifica que la sesión haya cambiado (de `None` a algo o que el valor sea distinto).

### 7. Session Timeout (CWE-613)

**Objetivo**: La sesión debe expirar automáticamente tras un período de inactividad (15 minutos en la demo).

- `test_session_expires`: Inicia sesión correctamente, accede al dashboard (`200`). Luego, con `patch` se avanza el tiempo 901 segundos (15 minutos + 1) y se intenta acceder de nuevo. El servidor debe redirigir (`302`) a la página de login.

### 8. No hardcoded secrets

**Objetivo**: La aplicación no debe tener secretos fijos en el código (al menos la `SECRET_KEY` se configura mediante entorno o generación segura).

- `test_secret_key_generated`: Verifica que la clave secreta de Flask no sea nula ni vacía. En entorno de pruebas se sobrescribe a `'test_secret_key'` para facilitar el testing.

## Ejecución de las pruebas

Desde la terminal, ejecutar:

```bash
pytest tests/test_auth.py -v
```

La opción `-v` muestra los nombres de las pruebas y su estado. Además, el logging configurado escribirá en consola y en `test_results.log`.

## Ejemplo de salida en consola y log

Al ejecutar la suite completa (todas las pruebas pasan), la consola mostrará algo similar a:

```
2025-03-25 10:30:15,123 | TEST | Testing IP rate limiting
2025-03-25 10:30:16,456 | TEST | IP rate limiting test passed
2025-03-25 10:30:16,457 | TEST | Testing rate limiting window reset
2025-03-25 10:30:16,789 | TEST | Rate limiting window test passed
2025-03-25 10:30:16,790 | TEST | Testing account lockout...
...
2025-03-25 10:30:20,123 | TEST | All tests passed.
```

Si alguna prueba falla, el log mostrará el error específico con el traceback y se escribirá en `test_results.log`. Por ejemplo:

```
FAILED test_account_lockout_progressive - AssertionError: assert 200 == 403
```

El archivo `test_results.log` contendrá el mismo detalle, siendo útil para depuración continua en entornos CI/CD.

## Resumen de cobertura de seguridad

| Mecanismo | Prueba implementada | CWE / OWASP |
|-----------|---------------------|--------------|
| Rate limiting por IP | `test_rate_limiting_ip` / `test_rate_limiting_window` | CWE-307 |
| Bloqueo progresivo de cuenta | `test_account_lockout_progressive` | CWE-307 |
| TOTP como segundo factor | `test_login_without_totp_fails` / `test_login_with_correct_totp_succeeds` | CWE-308 |
| Hashing bcrypt | `test_passwords_are_hashed` | A04:2021 |
| Anti-enumeración | `test_same_error_message` | CWE-287 |
| Regeneración de sesión | `test_session_id_changes_after_login` | CWE-384 |
| Timeout de sesión | `test_session_expires` | CWE-613 |
| Sin secretos fijos | `test_secret_key_generated` | CWE-798 |

## Notas adicionales

- Las pruebas utilizan `unittest.mock.patch` para manipular el tiempo sin dormir realmente el proceso, lo que hace la suite rápida y determinista.
- El estado global (`ip_attempts`, `user_lockouts`) se restablece automáticamente con el fixture `reset_state`, garantizando que una prueba no contamine a otra.
- La función `get_totp_code` depende de que el endpoint `/api/demo_totp/<username>` esté activo; en un entorno real se usaría un secreto TOTP configurado por el usuario.

Este conjunto de pruebas proporciona una base sólida para verificar que la aplicación cumple con las buenas prácticas de autenticación descritas en OWASP y mitiga los vectores de ataque más comunes.

