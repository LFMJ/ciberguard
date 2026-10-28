# CiberGuard

Plataforma interna para que los empleados reporten incidentes de ciberseguridad, el encargado de seguridad los gestione y la dirección vea el nivel de riesgo de la organización.

Versión de producción del MVP (`ciberguard-demo.html`): mismo flujo y misma fórmula de riesgo, ahora con inicio de sesión real, base de datos y control de acceso por rol.

## Roles

| Rol | Qué puede hacer |
|---|---|
| **Empleado** | Reportar incidentes, ver solo sus propios reportes y la respuesta de seguridad. |
| **Encargado de seguridad** | Todo lo del empleado + gestionar todos los incidentes (estado, severidad, asignación, notas), filtrar, exportar CSV y ver el panel de riesgo. |
| **Administrador** | Panel de riesgo, ver incidentes (solo lectura), reportar, **crear/editar/desactivar usuarios**, restablecer contraseñas y consultar la **bitácora de auditoría**. |

El administrador no puede modificar incidentes: así quien administra las cuentas no es quien atiende los incidentes (separación de funciones).

## Seguridad implementada

- Contraseñas guardadas con hash (`scrypt`/`pbkdf2` de Werkzeug), nunca en texto plano.
- Política de contraseñas: mínimo 10 caracteres, con letras y números, sin incluir el nombre de usuario.
- Contraseña temporal para usuarios nuevos o restablecidos, con **cambio obligatorio** en el primer ingreso.
- **Bloqueo de cuenta** por 15 minutos tras 5 intentos fallidos. Mismo mensaje de error y mismo tiempo de respuesta para un usuario inexistente que para una clave errada.
- Protección **CSRF** en todos los formularios, cookies `HttpOnly` + `SameSite=Lax` (+ `Secure` en producción), regeneración de sesión al ingresar y expiración a las 8 h.
- Cabeceras: `Content-Security-Policy` estricta (sin scripts en línea), `X-Frame-Options`, `nosniff`, `Referrer-Policy`, HSTS.
- Autorización en el servidor por rol. Un empleado que pide un incidente ajeno recibe 404.
- **Bitácora de auditoría**: ingresos, intentos fallidos, bloqueos, cambios de usuarios, cambios de incidentes y exportaciones, con la IP de origen.
- Exportación CSV protegida contra inyección de fórmulas de Excel. Sin redirecciones abiertas.

## Ejecutar en local

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export FLASK_APP=wsgi              # Windows PowerShell: $env:FLASK_APP="wsgi"
flask seed-demo                    # usuarios ana, carlos, laura, sofia — clave CiberGuard2026
flask run
```

Abre http://127.0.0.1:5000. Para un entorno real no uses `seed-demo`; crea el primer administrador con `flask create-admin`.

## Pruebas

```bash
pip install pytest
python -m pytest -q
```

19 pruebas: inicio de sesión y bloqueo, permisos de cada rol, aislamiento de los reportes entre empleados, gestión y auditoría, alta de usuarios con cambio obligatorio de clave, política de contraseñas, cálculo del riesgo, CSV, cabeceras y CSRF.

## Estructura

```
app/
  __init__.py     fábrica de la app, cabeceras de seguridad, comandos CLI
  models.py       User, Incident, AuditLog
  auth.py         ingreso, salida, cambio de contraseña, bloqueo
  incidents.py    reporte, gestión, detalle, CSV, panel
  admin.py        usuarios y auditoría
  risk.py         fórmula del nivel de riesgo
  security.py     control por rol, auditoría, política de claves
  templates/ static/
config.py         configuración (lee .env)
wsgi.py           punto de entrada para PythonAnywhere
tests/
```

Despliegue: ver [DESPLIEGUE_PYTHONANYWHERE.md](DESPLIEGUE_PYTHONANYWHERE.md).
