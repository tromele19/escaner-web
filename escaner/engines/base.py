"""Interfaz común de los motores de análisis."""

from __future__ import annotations

from abc import ABC, abstractmethod

from escaner.models import Category, Finding, ScanContext, ScanMode


class Engine(ABC):
    """Motor de análisis.

    Los motores trabajan sobre los datos ya descargados en ``ScanContext``
    (salvo el de rutas sensibles, que hace sus propias peticiones) y no
    deben lanzar excepciones por datos del sitio mal formados: un sitio
    hostil es la entrada normal de la herramienta.
    """

    #: Categoría a la que pertenecen todos los hallazgos del motor.
    category: Category
    #: Modos en los que se ejecuta el motor.
    modes: frozenset[ScanMode] = frozenset({ScanMode.PASSIVE, ScanMode.FULL})

    def applies_to(self, context: ScanContext) -> bool:
        """Indica si el motor debe ejecutarse para este contexto."""
        return context.mode in self.modes

    def is_evaluable(self, context: ScanContext) -> bool:
        """Indica si la categoría se puede evaluar en este sitio.

        Si no lo es (p. ej. un sitio que no usa cookies) la categoría aparece
        como «No aplica» y no cuenta en la nota global.
        """
        return True

    @abstractmethod
    def analyze(self, context: ScanContext) -> list[Finding]:
        """Analiza el contexto y devuelve la lista de hallazgos."""
