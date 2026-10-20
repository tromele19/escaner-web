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
| 29/09/2026 | Agente de programación | Integración continua (pruebas, ruff, bandit y pip-audit en Linux y Windows) y plantillas de issue y pull request | `.github/workflows/ci.yml`, `.github/ISSUE_TEMPLATE/tarea.md`, `.github/pull_request_template.md` | Revisión de los pasos frente al apartado 6.2 de la memoria |
| 20/10/2026 | Agente de programación | Validador de objetivo anti-SSRF (RF-01) y sus pruebas; Python 3.14 en la CI | `escaner/validator.py`, `tests/unit/test_validator.py`, `.github/workflows/ci.yml` | Lectura completa; pruebas manuales con DNS real y técnicas de evasión (IP decimal, hexadecimal, IPv4 en IPv6, metadatos 169.254.169.254); la primera integración quedó incompleta (ImportError en las pruebas) y se corrigió |
| 20/10/2026 | Agente de programación | Cliente HTTP con redirecciones seguras, límites de tiempo y tamaño, y sus pruebas (RF-02, RNF-02) | `escaner/acquisition/fetcher.py`, `tests/unit/test_fetcher.py` | Lectura completa; revisión de la revalidación anti-SSRF en cada redirección y del reintento sin verificar certificado; corregido el charset por defecto (requests asumía ISO-8859-1); prueba real contra badssl.com |
| 20/10/2026 | Agente de programación | Catálogo de reglas como datos (RNF-06) y motor de cabeceras de seguridad HTTP con 26 reglas y sus pruebas (RF-03) | `escaner/rules/__init__.py`, `escaner/rules/headers.py`, `escaner/engines/headers.py`, `tests/unit/test_headers.py` | Lectura completa; contraste de los criterios con la tabla 1 de la memoria, OWASP Secure Headers y MDN; ajuste de casos especiales (frame-ancestors sustituye a X-Frame-Options, nonce anula 'unsafe-inline', HSTS ignorado por HTTP); prueba real contra varios sitios |
