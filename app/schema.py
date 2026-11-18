"""Actualiza bases de datos existentes sin perder información.

db.create_all() crea tablas nuevas pero no agrega columnas a tablas que ya existen.
Aquí se agregan las columnas introducidas después de la primera versión.
"""
from sqlalchemy import inspect, text

from .extensions import db

NEW_COLUMNS = {
    "users": {
        "totp_secret": "VARCHAR(64)",
        "totp_enabled": "BOOLEAN NOT NULL DEFAULT 0",
        "totp_last_step": "INTEGER",
        "theme": "VARCHAR(10) NOT NULL DEFAULT 'oscuro'",
    },
    "incidents": {
        "first_response_at": "DATETIME",
        "personal_data": "VARCHAR(10) NOT NULL DEFAULT 'no_se'",
        "sic_reported_at": "DATE",
        "guided_json": "TEXT NOT NULL DEFAULT '{}'",
        "suggested_severity": "VARCHAR(10)",
        "anonymous": "BOOLEAN NOT NULL DEFAULT 0",
        "ioc_sender": "VARCHAR(200) NOT NULL DEFAULT ''",
        "ioc_domain": "VARCHAR(200) NOT NULL DEFAULT ''",
        "ioc_url": "VARCHAR(500) NOT NULL DEFAULT ''",
        "playbook_json": "TEXT NOT NULL DEFAULT '[]'",
        "root_cause": "TEXT NOT NULL DEFAULT ''",
        "lesson": "TEXT NOT NULL DEFAULT ''",
    },
}


def upgrade():
    insp = inspect(db.engine)
    added = []
    with db.engine.begin() as conn:
        for table, cols in NEW_COLUMNS.items():
            if not insp.has_table(table):
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in cols.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                    added.append(f"{table}.{name}")
        if "incidents.first_response_at" in added:
            # Incidentes ya atendidos antes de esta versión: se toma la última actualización como primera respuesta.
            conn.execute(text(
                "UPDATE incidents SET first_response_at = updated_at WHERE status != 'reportado'"
            ))
    return added
