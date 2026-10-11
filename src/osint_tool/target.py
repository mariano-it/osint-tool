"""Validación y normalización del objetivo."""

from __future__ import annotations

import re

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^({_LABEL}\.)+[a-z]{{2,63}}$")


class InvalidTarget(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    """Acepta un dominio o una URL completa y devuelve solo el host.

    Quita esquema, credenciales, puerto, ruta, query y punto final.
    """
    value = raw.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = re.split(r"[/?#]", value, maxsplit=1)[0]
    value = value.rsplit("@", 1)[-1]  # usuario:clave@host
    value = value.split(":", 1)[0].rstrip(".")  # puerto
    if not _DOMAIN_RE.match(value):
        raise InvalidTarget(f"'{raw}' no parece un dominio o URL válidos")
    return value


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def in_scope(host: str, target: str) -> bool:
    """¿`host` pertenece al objetivo autorizado?

    Acepta el propio objetivo, su variante con/sin `www.` y sus subdominios.
    Cualquier otro dominio (p. ej. tras una redirección) queda fuera.
    """
    h = _strip_www((host or "").lower().rstrip("."))
    t = _strip_www(target.lower())
    return bool(h) and (h == t or h.endswith("." + t))
