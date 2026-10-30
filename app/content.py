"""Contenido pensado para pymes: guías de respuesta, autoevaluación y microcapacitaciones."""

# ---------------------------------------------------------------------------
# 1. Qué hacer ahora: se muestra al empleado apenas reporta.
# ---------------------------------------------------------------------------
GUIDES = {
    "phishing": {
        "now": [
            "No respondas el mensaje ni abras sus enlaces o adjuntos.",
            "Si ya escribiste tu contraseña en el enlace, cámbiala ahora desde el sitio oficial (escribe la dirección tú mismo, no uses el enlace).",
            "Si usaste esa misma contraseña en otras cuentas, cámbiala también allá.",
            "Si diste datos bancarios, llama ya a tu banco con el número que aparece detrás de tu tarjeta.",
        ],
        "dont": ["No reenvíes el correo a tus compañeros «para avisar»: muéstraselo a seguridad.", "No lo borres todavía: puede servir como evidencia."],
    },
    "malware": {
        "now": [
            "Desconecta el equipo de la red: quita el cable o apaga el wifi. No lo apagues.",
            "No abras más archivos ni conectes memorias USB a ese equipo.",
            "Anota qué abriste, a qué hora y qué viste en pantalla (una foto con el celular sirve).",
            "Si aparece un mensaje pidiendo pago o rescate, no pagues ni respondas.",
        ],
        "dont": ["No intentes «limpiarlo» tú mismo con programas descargados de internet.", "No borres el archivo sospechoso."],
    },
    "contrasena": {
        "now": [
            "Si la contraseña expuesta es tuya, cámbiala ya por una nueva y larga (una frase de 4 palabras funciona bien).",
            "Activa la verificación en dos pasos en esa cuenta si el servicio lo permite.",
            "Si es de otra persona o de un equipo compartido, no la uses: avisa a seguridad para que la cambien.",
        ],
        "dont": ["No la anotes en papel ni en un archivo del escritorio.", "No compartas contraseñas por chat o correo."],
    },
    "acceso_indebido": {
        "now": [
            "Si notas actividad extraña en tu cuenta (correos enviados que no escribiste, inicios de sesión desconocidos), cambia tu contraseña ya.",
            "Cierra la sesión en todos los dispositivos desde la configuración de la cuenta.",
            "Si viste a alguien usando un equipo o una oficina sin autorización, no lo enfrentes: avisa a tu jefe y a seguridad.",
            "Anota fecha, hora y lo que viste.",
        ],
        "dont": ["No borres registros, correos ni archivos relacionados."],
    },
    "otro": {
        "now": [
            "Anota qué pasó, cuándo y qué equipos o cuentas están involucrados.",
            "Si sospechas que un equipo está comprometido, desconéctalo de la red sin apagarlo.",
            "Espera instrucciones del encargado de seguridad antes de hacer cambios.",
        ],
        "dont": ["No borres evidencia."],
    },
}

# ---------------------------------------------------------------------------
# 2. Autoevaluación de madurez basada en CIS Controls v8, grupo IG1
#    (las salvaguardas mínimas recomendadas para organizaciones pequeñas).
#    weight: 3 = crítico, 2 = importante, 1 = recomendado.
# ---------------------------------------------------------------------------
ANSWERS = {"si": "Sí", "parcial": "En parte", "no": "No", "no_se": "No sé"}
ANSWER_VALUE = {"si": 1.0, "parcial": 0.5, "no": 0.0, "no_se": 0.0}

QUESTIONS = [
    # (id, área, control CIS, peso, pregunta, recomendación si la respuesta no es «Sí», esfuerzo)
    ("inventario_equipos", "Inventario", "CIS 1", 2,
     "¿Tienen una lista actualizada de todos los computadores, celulares y equipos de la empresa y quién los usa?",
     "Haz una hoja de cálculo con cada equipo: tipo, responsable, sistema operativo y fecha de compra. Revísala cada trimestre.", "Bajo"),
    ("inventario_software", "Inventario", "CIS 2", 1,
     "¿Saben qué programas están instalados en los equipos y se eliminan los que no se usan o no tienen licencia?",
     "Define una lista de programas permitidos y desinstala lo que no esté en ella. Los programas piratas suelen traer malware.", "Bajo"),
    ("datos_sensibles", "Protección de datos", "CIS 3", 3,
     "¿Saben dónde están guardados los datos sensibles (clientes, nómina, contabilidad) y quién tiene acceso?",
     "Identifica dónde están los datos personales y financieros, y deja el acceso solo a quien lo necesita para su trabajo. Lo exige la Ley 1581 de 2012.", "Medio"),
    ("cifrado", "Protección de datos", "CIS 3", 2,
     "¿Los portátiles y celulares de la empresa tienen el disco cifrado (BitLocker, FileVault o el cifrado del celular)?",
     "Activa BitLocker (Windows) o FileVault (Mac) en todos los portátiles. Si un equipo se pierde, los datos no se pueden leer.", "Bajo"),
    ("actualizaciones", "Configuración segura", "CIS 7", 3,
     "¿Los equipos instalan automáticamente las actualizaciones del sistema operativo y de los navegadores?",
     "Activa las actualizaciones automáticas en todos los equipos y revisa una vez al mes que estén al día.", "Bajo"),
    ("config_segura", "Configuración segura", "CIS 4", 2,
     "¿Los equipos tienen bloqueo automático de pantalla y el firewall activado?",
     "Configura bloqueo de pantalla a los 5 minutos y verifica que el firewall de Windows o macOS esté encendido.", "Bajo"),
    ("admin_separado", "Cuentas y accesos", "CIS 5", 2,
     "¿Los empleados trabajan con cuentas normales, sin permisos de administrador en sus equipos?",
     "Quita los permisos de administrador del uso diario. Así el malware no se puede instalar con los permisos del usuario.", "Medio"),
    ("bajas", "Cuentas y accesos", "CIS 5", 3,
     "Cuando alguien se retira de la empresa, ¿se desactivan sus cuentas (correo, sistemas, wifi) el mismo día?",
     "Crea una lista de chequeo de retiro: correo, sistemas contables, nube, wifi y llaves. Que se ejecute el último día de trabajo.", "Bajo"),
    ("mfa", "Cuentas y accesos", "CIS 6", 3,
     "¿El correo y los sistemas en la nube usan verificación en dos pasos?",
     "Activa la verificación en dos pasos en el correo (Google Workspace o Microsoft 365) y en la banca en línea. Es la medida que más ataques detiene.", "Bajo"),
    ("contrasenas", "Cuentas y accesos", "CIS 5", 2,
     "¿Cada persona tiene su propia cuenta y contraseña (no se comparten usuarios) y se usan contraseñas largas y distintas?",
     "Elimina las cuentas compartidas y adopta un gestor de contraseñas (Bitwarden tiene versión gratuita).", "Bajo"),
    ("antimalware", "Defensa contra malware", "CIS 10", 3,
     "¿Todos los equipos tienen antivirus activo y actualizado?",
     "Windows Defender es suficiente si está activo y actualizado. Verifica que ningún equipo lo tenga deshabilitado.", "Bajo"),
    ("copias", "Recuperación", "CIS 11", 3,
     "¿Hacen copias de seguridad automáticas de la información importante, con al menos una copia fuera de la oficina o desconectada?",
     "Aplica la regla 3-2-1: 3 copias, en 2 medios distintos, 1 fuera de la oficina o desconectada. Protege contra ransomware e incendios.", "Medio"),
    ("restauracion", "Recuperación", "CIS 11", 2,
     "¿Han probado restaurar una copia de seguridad en los últimos 6 meses?",
     "Programa una prueba de restauración cada semestre. Una copia que nunca se ha probado puede no servir.", "Bajo"),
    ("wifi", "Red", "CIS 12", 1,
     "¿La red wifi de visitantes está separada de la red de la empresa y la clave del router no es la de fábrica?",
     "Crea una red de invitados aparte y cambia la contraseña de administración del router.", "Bajo"),
    ("capacitacion", "Personas", "CIS 14", 3,
     "¿Los empleados reciben capacitación en seguridad (phishing, contraseñas) al menos una vez al año?",
     "Pide a cada empleado completar la microcapacitación de CiberGuard cada trimestre y comenten los resultados en una reunión.", "Bajo"),
    ("respuesta", "Respuesta a incidentes", "CIS 17", 2,
     "¿Hay una persona responsable de atender incidentes y todos saben cómo reportarlos?",
     "Designa un encargado de seguridad y comunica a todos que los incidentes se reportan en CiberGuard.", "Bajo"),
    ("proveedores", "Proveedores", "CIS 15", 1,
     "¿Saben qué proveedores tienen acceso a sus sistemas o datos y revisan que lo protejan?",
     "Haz una lista de proveedores con acceso (contador, soporte técnico, software en la nube) e incluye cláusulas de confidencialidad en los contratos.", "Medio"),
]
QUESTION_IDS = [q[0] for q in QUESTIONS]


def maturity_score(answers):
    total = sum(q[3] for q in QUESTIONS)
    got = sum(q[3] * ANSWER_VALUE.get(answers.get(q[0], "no_se"), 0) for q in QUESTIONS)
    return round(got / total * 100)


def maturity_level(score):
    if score >= 80:
        return "alta", "Madurez alta"
    if score >= 50:
        return "media", "Madurez media"
    return "baja", "Madurez baja"


def action_plan(answers):
    """Acciones pendientes ordenadas por impacto: primero lo crítico y lo que está en «No»."""
    pending = []
    for qid, area, cis, weight, text, rec, effort in QUESTIONS:
        a = answers.get(qid, "no_se")
        if a != "si":
            gap = weight * (1 - ANSWER_VALUE.get(a, 0))
            pending.append({"id": qid, "area": area, "cis": cis, "weight": weight, "question": text,
                            "action": rec, "effort": effort, "answer": a, "gap": gap})
    return sorted(pending, key=lambda p: (-p["gap"], p["effort"] != "Bajo"))


# ---------------------------------------------------------------------------
# 3. Microcapacitación: «¿Esto es phishing?» y buenas prácticas.
# ---------------------------------------------------------------------------
QUIZ = [
    {
        "id": "q1",
        "scenario": "Te llega un correo de «Bancolombia Seguridad» <alertas@bancolombia-verificacion.co>: «Detectamos un acceso inusual. Confirma tus datos en las próximas 2 horas o tu cuenta será bloqueada».",
        "options": ["Hago clic y confirmo mis datos para que no me bloqueen", "Es phishing: no hago clic y lo reporto en CiberGuard", "Respondo el correo preguntando si es real"],
        "answer": 1,
        "why": "El dominio no es el oficial del banco, y la urgencia («2 horas», «será bloqueada») es la señal clásica de phishing. Los bancos no piden confirmar datos por correo.",
    },
    {
        "id": "q2",
        "scenario": "Tu jefe te escribe por WhatsApp desde un número nuevo: «Estoy en reunión, necesito que pagues hoy esta factura urgente a este proveedor. No me llames».",
        "options": ["Hago el pago, es mi jefe", "Verifico llamando al número que ya tengo guardado de mi jefe antes de pagar", "Le pido que me mande la factura por correo y pago"],
        "answer": 1,
        "why": "Es el «fraude del CEO»: suplantan a un directivo, piden urgencia y evitan que verifiques. Confirma siempre por un canal que ya conoces.",
    },
    {
        "id": "q3",
        "scenario": "Recibes un correo de un proveedor conocido con un adjunto «Factura_Octubre.pdf.exe».",
        "options": ["Lo abro, es un proveedor conocido", "No lo abro: un PDF real no termina en .exe; lo reporto", "Lo reenvío a contabilidad para que ellos lo abran"],
        "answer": 1,
        "why": "La doble extensión «.pdf.exe» esconde un programa ejecutable. La cuenta del proveedor pudo haber sido comprometida.",
    },
    {
        "id": "q4",
        "scenario": "¿Cuál de estas contraseñas es más segura?",
        "options": ["Empresa2026!", "P@ssw0rd", "cafe-montaña-lluvia-bicicleta"],
        "answer": 2,
        "why": "La longitud es lo que más pesa. Una frase de cuatro palabras al azar es más difícil de adivinar y más fácil de recordar que una palabra corta con símbolos.",
    },
    {
        "id": "q5",
        "scenario": "Encuentras una memoria USB en el parqueadero con una etiqueta que dice «Nómina 2026».",
        "options": ["La conecto para ver de quién es", "La entrego al encargado de seguridad sin conectarla", "La conecto en un equipo que no sea el mío"],
        "answer": 1,
        "why": "Dejar memorias «olvidadas» es una técnica real para infectar empresas. Conectarla en cualquier equipo de la red es igual de riesgoso.",
    },
    {
        "id": "q6",
        "scenario": "Alguien llama diciendo que es de soporte técnico de Microsoft y te pide un código que te acaba de llegar por SMS para «verificar tu cuenta».",
        "options": ["Le doy el código, es de soporte", "Cuelgo: nadie legítimo pide ese código; lo reporto", "Le doy el código pero cambio mi clave después"],
        "answer": 1,
        "why": "Ese código es tu segundo factor. Quien lo pide está intentando entrar a tu cuenta. Ningún soporte real lo solicita.",
    },
    {
        "id": "q7",
        "scenario": "Te vas a almorzar y dejas tu computador encendido en el escritorio.",
        "options": ["No pasa nada, la oficina es segura", "Bloqueo la pantalla con Windows + L antes de irme", "Apago solo el monitor"],
        "answer": 1,
        "why": "Un equipo desbloqueado permite a cualquiera leer correos, enviar mensajes en tu nombre o copiar archivos en segundos.",
    },
    {
        "id": "q8",
        "scenario": "Un cliente te pide que le envíes por correo la base de datos completa de clientes «para revisar su información».",
        "options": ["Se la envío, es un cliente", "Solo le envío su propia información, por un canal seguro, y consulto con mi jefe", "La subo a una carpeta pública para que la descargue"],
        "answer": 1,
        "why": "Compartir datos de otros clientes viola la Ley 1581 de 2012 de protección de datos personales. Cada titular solo puede acceder a su propia información.",
    },
]


# ---------------------------------------------------------------------------
# 4. Preguntas guiadas al reportar. Cada respuesta «Sí» puede subir la severidad sugerida.
#    (id, pregunta, severidad si la respuesta es «Sí», motivo que verá seguridad)
# ---------------------------------------------------------------------------
GUIDED = {
    "phishing": [
        ("clic", "¿Hiciste clic en el enlace o abriste un adjunto?", "media", "abrió el enlace o el adjunto"),
        ("clave", "¿Escribiste tu usuario o contraseña en la página?", "alta", "escribió su contraseña en la página falsa"),
        ("banco", "¿Diste datos bancarios, de tarjeta o hiciste un pago?", "alta", "entregó datos bancarios o pagó"),
        ("respondio", "¿Respondiste el mensaje?", "media", "respondió al atacante"),
    ],
    "malware": [
        ("abrio", "¿Abriste el archivo o ejecutaste el programa?", "media", "abrió o ejecutó el archivo"),
        ("raro", "¿El equipo se comporta raro (lento, ventanas, archivos que cambian)?", "alta", "el equipo muestra síntomas"),
        ("rescate", "¿Apareció un mensaje pidiendo pago o rescate?", "alta", "posible ransomware"),
        ("red", "¿El equipo sigue conectado a la red de la empresa?", "media", "el equipo sigue en la red"),
    ],
    "contrasena": [
        ("propia", "¿La contraseña expuesta es tuya?", "media", "contraseña propia expuesta"),
        ("critica", "¿Da acceso al correo, al banco o a sistemas de la empresa?", "alta", "da acceso a sistemas críticos"),
        ("usada", "¿Crees que alguien ya la usó?", "alta", "posible uso por un tercero"),
    ],
    "acceso_indebido": [
        ("cuenta", "¿Notaste actividad en una cuenta que no hiciste tú?", "alta", "actividad no reconocida en una cuenta"),
        ("fisico", "¿Alguien entró físicamente a un área o equipo sin permiso?", "media", "acceso físico no autorizado"),
        ("envio", "¿Se envió información a quien no debía?", "alta", "información enviada a un tercero"),
    ],
    "otro": [],
}
GUIDED_ANSWERS = {"si": "Sí", "no": "No", "no_se": "No sé"}
SEVERITY_RANK = {"baja": 0, "media": 1, "alta": 2}


def suggest_severity(type_, answers, personal_data):
    """Severidad sugerida y los motivos. Con datos personales expuestos siempre es alta."""
    reasons, level = [], None
    for qid, _text, sev, why in GUIDED.get(type_, []):
        if answers.get(qid) == "si":
            reasons.append(why)
            level = sev if level is None or SEVERITY_RANK[sev] > SEVERITY_RANK[level] else level
    if personal_data == "si":
        reasons.append("posible exposición de datos personales")
        level = "alta"
    if level is None:
        qs = GUIDED.get(type_, [])
        answered_no = qs and all(answers.get(q[0]) == "no" for q in qs)
        level = "baja" if answered_no and personal_data == "no" else "media"
        if answered_no and personal_data == "no":
            reasons.append("no hubo interacción ni datos expuestos")
    return level, reasons


# ---------------------------------------------------------------------------
# 5. Guías de respuesta para el encargado de seguridad (fases de NIST SP 800-61).
#    La fase «Lecciones aprendidas» se completa con los campos causa y medida preventiva.
# ---------------------------------------------------------------------------
PLAYBOOKS = {
    "phishing": [
        ("Contención", [
            ("ph1", "Pedir al empleado que no interactúe más y conserve el mensaje como evidencia."),
            ("ph2", "Si escribió su contraseña: cambiarla ya y cerrar sesiones abiertas en todos los dispositivos."),
            ("ph3", "Buscar si otros empleados recibieron el mismo mensaje y advertirles."),
        ]),
        ("Erradicación", [
            ("ph4", "Bloquear el remitente y el dominio en el filtro de correo."),
            ("ph5", "Eliminar el mensaje de los buzones que lo recibieron."),
            ("ph6", "Si hubo datos bancarios: contactar al banco para bloquear tarjetas o pagos."),
        ]),
        ("Recuperación", [
            ("ph7", "Activar la verificación en dos pasos en la cuenta afectada."),
            ("ph8", "Revisar reglas de reenvío o actividad extraña en el correo durante 7 días."),
        ]),
    ],
    "malware": [
        ("Contención", [
            ("mw1", "Desconectar el equipo de la red (cable y wifi) sin apagarlo."),
            ("mw2", "Identificar el archivo, su origen y la hora en que se abrió."),
            ("mw3", "Revisar si otros equipos recibieron o abrieron el mismo archivo."),
        ]),
        ("Erradicación", [
            ("mw4", "Ejecutar un análisis completo con el antivirus actualizado."),
            ("mw5", "Si persiste o hay rescate: reinstalar el sistema operativo desde cero."),
            ("mw6", "Cambiar las contraseñas usadas en ese equipo desde otro equipo limpio."),
        ]),
        ("Recuperación", [
            ("mw7", "Restaurar archivos desde una copia de seguridad anterior al incidente."),
            ("mw8", "Volver a conectar el equipo y vigilarlo durante una semana."),
        ]),
    ],
    "contrasena": [
        ("Contención", [
            ("pw1", "Cambiar la contraseña expuesta por una nueva y larga."),
            ("pw2", "Cerrar las sesiones abiertas de esa cuenta."),
        ]),
        ("Erradicación", [
            ("pw3", "Retirar el papel, archivo o mensaje donde quedó escrita."),
            ("pw4", "Cambiarla también en otros servicios donde se reutilizaba."),
        ]),
        ("Recuperación", [
            ("pw5", "Activar la verificación en dos pasos en la cuenta."),
            ("pw6", "Revisar los accesos recientes de la cuenta en busca de uso indebido."),
        ]),
    ],
    "acceso_indebido": [
        ("Contención", [
            ("ac1", "Bloquear la cuenta o el acceso comprometido."),
            ("ac2", "Si es físico: retirar credenciales o llaves y avisar a la administración."),
            ("ac3", "Conservar registros de acceso, correos y cámaras como evidencia."),
        ]),
        ("Erradicación", [
            ("ac4", "Cambiar contraseñas y revisar los permisos de la cuenta afectada."),
            ("ac5", "Si se envió información: pedir al destinatario que la elimine y lo confirme por escrito."),
        ]),
        ("Recuperación", [
            ("ac6", "Restablecer el acceso legítimo con verificación en dos pasos."),
            ("ac7", "Evaluar si debe reportarse a la SIC (datos personales)."),
        ]),
    ],
    "otro": [
        ("Contención", [("ot1", "Delimitar qué equipos, cuentas o datos están involucrados.")]),
        ("Erradicación", [("ot2", "Eliminar la causa identificada.")]),
        ("Recuperación", [("ot3", "Volver a la operación normal y vigilar.")]),
    ],
}
PLAYBOOK_STEPS = {sid: text for phases in PLAYBOOKS.values() for _p, steps in phases for sid, text in steps}


def playbook_progress(type_, done):
    ids = [sid for _p, steps in PLAYBOOKS.get(type_, []) for sid, _t in steps]
    if not ids:
        return 0, 0
    return sum(1 for s in ids if s in done), len(ids)


# ---------------------------------------------------------------------------
# 6. Recordatorios periódicos. «auto» se calcula con los datos; «manual» se marca como hecho.
#    (clave, título, cada cuántos días, tipo, explicación)
# ---------------------------------------------------------------------------
REMINDERS = [
    ("autoevaluacion", "Actualizar la autoevaluación de madurez", 90, "auto",
     "Repetirla cada trimestre muestra si el plan de acción está funcionando."),
    ("capacitacion", "Pedir la microcapacitación a quienes estén pendientes", 90, "auto",
     "Cada persona debería hacerla al menos una vez por trimestre."),
    ("restauracion", "Probar la restauración de una copia de seguridad", 180, "manual",
     "Una copia que nunca se ha probado puede no servir el día que se necesite."),
    ("cuentas", "Revisar cuentas de personas retiradas y permisos", 30, "manual",
     "Desactivar accesos de quien ya no trabaja en la empresa (correo, sistemas, wifi)."),
    ("actualizaciones", "Verificar que los equipos tengan las actualizaciones al día", 30, "manual",
     "Sistema operativo, navegadores y antivirus."),
]
