# Registro de uso de IA

Este fichero documenta cada uso relevante de asistentes de IA durante el desarrollo del proyecto, tal y como se describe en el apartado 6.4 de la memoria. Se incluirá como anexo en las entregas.

## Flujo de trabajo

1. **Definición de la tarea** — issue en GitHub con entradas, salidas, casos límite y criterio de aceptación (enlazado al RF/RNF).
2. **Pruebas primero** — casos de prueba con respuestas HTTP simuladas antes de la implementación.
3. **Generación** — implementación acotada a la tarea en una rama `feature/<tarea>`.
4. **Revisión manual** — lectura línea a línea (reglas de seguridad, errores de red/TLS, saneado para la IA, consultas SQL).
5. **Verificación automática** — `pytest`, `ruff` y `bandit` antes de integrar.
6. **Integración y trazabilidad** — pull request a `main`; commits con la etiqueta `[IA]` y entrada en este registro.

Regla: **no se integra código que no se entienda completamente**; si una parte generada no se puede explicar, se reescribe.

## Registro

| Fecha | Herramienta | Tarea | Ficheros | Revisión realizada |
|---|---|---|---|---|
| 29/09/2026 | Agente de programación | Esqueleto inicial del repositorio: estructura de capas, `pyproject.toml`, README, modelos de datos, interfaz de los motores y CLI mínima | Estructura completa, `escaner/models.py`, `escaner/engines/base.py`, `escaner/cli.py`, `tests/unit/test_models.py` | Revisión de la estructura frente al apartado 8.3 de la memoria; comprobación de que `pytest` y `ruff` pasan |
