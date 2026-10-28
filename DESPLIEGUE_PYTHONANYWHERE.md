# Despliegue en PythonAnywhere

## ¿Es factible?

**Sí, para la entrega y la demostración.** CiberGuard es una app Flask (WSGI) con SQLite y sin dependencias externas, que es justo lo que PythonAnywhere sirve bien. La cuenta gratuita alcanza para presentar el proyecto. Para un uso real y continuo en una empresa conviene el plan pago.

| Aspecto | Cuenta gratuita | Impacto en CiberGuard |
|---|---|---|
| Web apps | 1 app, 1 worker, en `usuario.pythonanywhere.com` con HTTPS | ✅ Suficiente. El HTTPS viene incluido. |
| Expiración | La app se desactiva si no se renueva **cada mes** | ⚠️ Antes de la sustentación, entra a la pestaña *Web* y pulsa **"Run until 1 month from today"**. |
| Base de datos | Las cuentas creadas después del 15‑ene‑2026 **ya no tienen MySQL** | ✅ La app usa SQLite por defecto, que funciona sin configurar nada. |
| CPU | 100 segundos de CPU al día (consolas y tareas) | ✅ Las peticiones web no consumen esa cuota. Solo cuentan la instalación y los comandos. |
| Disco | 512 MiB | ✅ El proyecto con su entorno virtual ocupa alrededor de 50 MB. |
| Internet saliente | Solo HTTP(S) hacia una lista de sitios permitidos | ➖ No afecta. La app no llama servicios externos. Limitaría a futuro el envío de correos de alerta. |
| Tareas programadas / SSH | No incluidas en cuentas nuevas | ➖ No se necesitan. Los respaldos se hacen a mano (ver abajo). |
| Dominio propio | No | ➖ Solo con plan pago. |
| Soporte | Solo foros desde ene‑2026 | ➖ |

**Plan pago (Developer, unos 10 USD/mes):** quita la expiración mensual e incluye MySQL, tareas programadas para respaldos automáticos y dominio propio. Es lo recomendado si la empresa lo va a usar a diario.

**¿SQLite es suficiente?** Para una pyme (decenas de empleados, pocos reportes al día) sí: hay un solo worker y las escrituras son pequeñas. Si más adelante se necesita MySQL, basta con definir `DATABASE_URL` en `.env` e instalar `pymysql`. El código no cambia.

> Datos tomados de la [página oficial de la cuenta gratuita](https://help.pythonanywhere.com/pages/FreeAccountsFeatures/) y del [anuncio de cambios de diciembre de 2025](https://blog.pythonanywhere.com/221/). PythonAnywhere ajusta sus planes, así que verifícalos antes de pagar.

---

## Paso a paso (unos 15 minutos)

En los comandos, reemplaza `TUUSUARIO` por tu usuario de PythonAnywhere.

### 1. Crear la cuenta y subir el código

1. Regístrate en https://www.pythonanywhere.com (plan *Beginner*, gratuito).
2. Abre **Consoles → Bash** y trae el código.

   Con GitHub:
   ```bash
   git clone https://github.com/TU_ORG/ciberguard.git
   ```
   O sin GitHub: comprime la carpeta en un `.zip`, súbelo en la pestaña **Files** y descomprímelo:
   ```bash
   unzip ciberguard.zip -d ~/ciberguard
   ```

### 2. Entorno virtual y dependencias

```bash
cd ~/ciberguard
python3.13 -m venv .venv
```
```bash
source .venv/bin/activate
```
```bash
pip install -r requirements.txt
```

(Si tu cuenta no tiene `python3.13`, usa la versión más reciente que liste `ls /usr/bin/python3*`. Sirve cualquier versión 3.10 o superior.)

### 3. Configuración secreta

```bash
cp .env.example .env
```
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Abre `.env` en la pestaña **Files** y pega esa clave en `SECRET_KEY=`. Deja `SESSION_COOKIE_SECURE=1`. **No subas el `.env` a GitHub**: ya está en `.gitignore`.

### 4. Crear la base de datos y el primer administrador

```bash
export FLASK_APP=wsgi
```
```bash
flask create-admin
```

Solo para la presentación, si quieres los datos de ejemplo de la demo (ana, carlos, laura, sofia con clave `CiberGuard2026`):

```bash
flask seed-demo
```

### 5. Crear la web app

1. Pestaña **Web → Add a new web app → Next → Manual configuration** (no elijas "Flask": esa opción crea su propio proyecto) → elige la **misma versión de Python** del paso 2.
2. En la sección **Virtualenv**, escribe `/home/TUUSUARIO/ciberguard/.venv`.
3. En **Code**, abre el enlace del *WSGI configuration file* (`/var/www/TUUSUARIO_pythonanywhere_com_wsgi.py`), borra todo su contenido y deja solo esto:

   ```python
   import sys
   path = "/home/TUUSUARIO/ciberguard"
   if path not in sys.path:
       sys.path.insert(0, path)

   from wsgi import application  # noqa
   ```

4. En **Static files**, agrega URL `/static/` y directorio `/home/TUUSUARIO/ciberguard/app/static`.
5. En **Security**, activa **Force HTTPS**.
6. Pulsa el botón verde **Reload**. Abre `https://TUUSUARIO.pythonanywhere.com` e ingresa.

### 6. Actualizar después de un cambio

```bash
cd ~/ciberguard && git pull
```
```bash
source .venv/bin/activate && pip install -r requirements.txt
```

Luego pulsa **Reload** en la pestaña *Web*. Las tablas nuevas se crean solas al arrancar.

### 7. Respaldos

Toda la información está en un solo archivo: `~/ciberguard/instance/ciberguard.db`. Para descargarlo, ve a la pestaña **Files** → `ciberguard/instance` → *download*. Para una copia rápida desde la consola:

```bash
cp ~/ciberguard/instance/ciberguard.db ~/respaldo-$(date +%F).db
```

## Si algo falla

- **"Something went wrong" / error 500:** revisa el *Error log* en la pestaña *Web*. Lo más común es una ruta mal escrita en el archivo WSGI o un virtualenv de otra versión de Python.
- **No puedo iniciar sesión, "el formulario expiró" (400):** falta `SECRET_KEY` en `.env`, o se cambió y las sesiones viejas dejaron de valer. Recarga la página.
- **Se ve sin estilos:** revisa el mapeo de *Static files* del paso 5.4.
- **Cuenta bloqueada por intentos:** espera 15 minutos o pide al administrador que la desbloquee en *Usuarios → Editar*.

## Antes de usarlo en serio (fuera del alcance académico)

- Pasar a plan pago para quitar la expiración y programar respaldos diarios.
- Agregar notificaciones por correo al encargado de seguridad. En la cuenta gratuita el internet saliente está restringido.
- Considerar doble factor (TOTP) para los roles de administrador y seguridad.
