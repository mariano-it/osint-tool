"""Registro de módulos: cada módulo se anuncia con @register."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from osint_tool.modules.base import Module

_REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    if cls.name in _REGISTRY:
        raise ValueError(f"módulo duplicado: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def available() -> dict[str, type[Module]]:
    # Importar el paquete dispara el @register de cada módulo.
    import osint_tool.modules  # noqa: F401

    return dict(sorted(_REGISTRY.items()))


def get(name: str) -> type[Module]:
    modules = available()
    if name not in modules:
        known = ", ".join(modules) or "(ninguno)"
        raise KeyError(f"módulo desconocido '{name}'. Disponibles: {known}")
    return modules[name]
