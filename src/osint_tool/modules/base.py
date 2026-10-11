"""Contrato que cumple todo módulo de reconocimiento."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from osint_tool.models import ModuleResult


class Module(ABC):
    name: ClassVar[str]
    description: ClassVar[str]

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    @abstractmethod
    def run(self, target: str) -> ModuleResult:
        """Analiza `target` (dominio ya normalizado) y devuelve el resultado."""
