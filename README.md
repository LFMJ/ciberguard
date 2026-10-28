# CiberGuard

Plataforma interna para que los empleados reporten incidentes de ciberseguridad, el encargado de seguridad los gestione y la dirección vea el nivel de riesgo de la organización.

Versión de producción del MVP (`ciberguard-demo.html`): mismo flujo y misma fórmula de riesgo, ahora con inicio de sesión real, base de datos y control de acceso por rol.

## Roles

| Rol | Qué puede hacer |
|---|---|
| **Empleado** | Reportar incidentes con evidencia, recibir la guía de qué hacer, ver solo sus propios reportes y hacer la microcapacitación. |
| **Encargado de seguridad** | Todo lo del empleado + gestionar todos los incidentes (estado, severidad, asignación, notas, datos personales, reporte a la SIC), filtrar, exportar CSV, panel de riesgo, autoevaluación, reporte mensual y resultados de capacitación del equipo. |
| **Administrador** | Panel, autoevaluación, reporte mensual y capacitación; ver incidentes (solo lectura); **crear/editar/desactivar usuarios**, restablecer contraseñas o la verificación en dos pasos, y consultar la **bitácora de auditoría**. |

El administrador no puede modificar incidentes: así quien administra las cuentas no es quien atiende los incidentes (separación de funciones).

## Funciones pensadas para pymes

- **Qué hacer ahora:** al reportar, el empleado recibe pasos inmediatos según el tipo de incidente (phishing, malware, contraseñas, acceso indebido).
- **Autoevaluación de madurez:** 17 preguntas basadas en los **CIS Controls v8 (grupo IG1)**. Entrega un puntaje de 0 a 100, el resultado por área y un plan de acción priorizado por impacto y esfuerzo.
- **Panel de riesgo global:** combina el riesgo por incidentes (60 %) con la brecha de madurez (40 %) y muestra la evolución semanal, el cumplimiento de tiempos de atención, la cobertura de capacitación y los incidentes con datos personales pendientes.
- **Tiempos de atención (SLA):** alta 4 h, media 24 h, baja 72 h. Los incidentes fuera de plazo se marcan y se pueden filtrar.
- **Evidencia adjunta:** capturas PNG/JPG o PDF (2 MB c/u, máx. 5 por incidente). Se valida el contenido real del archivo y solo lo ven el empleado que reportó y el equipo de seguridad.
- **Ley 1581 de 2012:** los incidentes con datos personales muestran la fecha de referencia para reportar ante la SIC (15 días hábiles desde la detección) y permiten registrar cuándo se reportó.
- **Microcapacitación:** 8 situaciones reales («¿esto es phishing?») con explicación. El equipo de seguridad ve quién está al día en los últimos 90 días.
- **Reporte mensual** listo para imprimir o guardar en PDF, pensado para la gerencia.
- **Verificación en dos pasos (TOTP)** con Google o Microsoft Authenticator. Se recomienda en pantalla para administradores y encargados de seguridad.

## Seguridad implementada

- Contraseñas guardadas con hash (`scrypt`/`pbkdf2` de Werkzeug), nunca en texto plano.
- Política de contraseñas: mínimo 10 caracteres, con letras y números, sin incluir el nombre de usuario.
- Verificación en dos pasos opcional (RFC 6238) con protección contra reutilización de códigos; los intentos fallidos cuentan para el bloqueo.
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
flask seed-demo                    # usuarios ana, carlos, laura, sofia — clave CiberGuard2026, con incidentes, autoevaluación y capacitación de ejemplo
flask run
```

Abre http://127.0.0.1:5000. Para un entorno real no uses `seed-demo`; crea el primer administrador con `flask create-admin`.

## Pruebas

```bash
pip install pytest
python -m pytest -q
```

29 pruebas: inicio de sesión, bloqueo y verificación en dos pasos, permisos de cada rol, aislamiento de reportes y evidencia entre empleados, gestión y auditoría, tiempos de atención, flujo de datos personales y SIC, autoevaluación, capacitación, reporte mensual, cálculo del riesgo, CSV, cabeceras, CSRF y actualización de bases de datos antiguas.

## Estructura

```
app/
  __init__.py     fábrica de la app, cabeceras de seguridad, comandos CLI
  models.py       User, Incident, Attachment, Assessment, QuizAttempt, AuditLog
  auth.py         ingreso, doble factor, cambio de contraseña, bloqueo
  incidents.py    reporte, gestión, detalle, evidencia, CSV, panel, reporte mensual
  admin.py        usuarios y auditoría
  risk.py         riesgo por incidentes, global, tendencia y reporte mensual
  content.py      guías de respuesta, preguntas CIS IG1 y microcapacitación
  assessment.py   autoevaluación de madurez
  training.py     microcapacitación y resultados del equipo
  totp.py         verificación en dos pasos
  uploads.py      evidencia adjunta
  compliance.py   plazos de la Ley 1581 / SIC
  schema.py       agrega columnas nuevas a bases de datos existentes
  security.py     control por rol, auditoría, política de claves
  templates/ static/
config.py         configuración (lee .env)
wsgi.py           punto de entrada para PythonAnywhere
tests/
```

Despliegue: ver [DESPLIEGUE_PYTHONANYWHERE.md](DESPLIEGUE_PYTHONANYWHERE.md).
