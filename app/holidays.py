"""Festivos de Colombia (Ley 51 de 1983, «Ley Emiliani»), calculados para cualquier año."""
from datetime import date, timedelta
from functools import lru_cache

FIXED = [(1, 1, "Año Nuevo"), (5, 1, "Día del Trabajo"), (7, 20, "Independencia"), (8, 7, "Batalla de Boyacá"),
         (12, 8, "Inmaculada Concepción"), (12, 25, "Navidad")]
# Se trasladan al lunes siguiente si no caen en lunes.
MOVED = [(1, 6, "Reyes Magos"), (3, 19, "San José"), (6, 29, "San Pedro y San Pablo"), (8, 15, "Asunción de la Virgen"),
         (10, 12, "Día de la Raza"), (11, 1, "Todos los Santos"), (11, 11, "Independencia de Cartagena")]
# Días después del domingo de Pascua; los tres últimos ya incluyen el traslado al lunes.
EASTER = [(-3, "Jueves Santo"), (-2, "Viernes Santo"), (43, "Ascensión del Señor"), (64, "Corpus Christi"),
          (71, "Sagrado Corazón")]


def easter(year):
    """Domingo de Pascua (algoritmo de Meeus/Jones/Butcher)."""
    a, b, c = year % 19, year // 100, year % 100
    d, e = b // 4, b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7  # noqa: E741
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = (h + l - 7 * m + 114) % 31 + 1
    return date(year, month, day)


def _next_monday(d):
    return d + timedelta(days=(7 - d.weekday()) % 7)


@lru_cache(maxsize=16)
def colombia(year):
    """Lista ordenada de (fecha, nombre)."""
    out = [(date(year, m, d), n) for m, d, n in FIXED]
    out += [(_next_monday(date(year, m, d)), n) for m, d, n in MOVED]
    e = easter(year)
    out += [(e + timedelta(days=k), n) for k, n in EASTER]
    return tuple(sorted(out))


def is_holiday(d):
    return any(h == d for h, _ in colombia(d.year))
