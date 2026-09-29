# Escáner de Seguridad Web con IA

Herramienta de línea de comandos en Python que audita la **configuración de seguridad** de un sitio web a partir de su URL, calcula una nota de la **A a la F** y genera un informe explicativo y un plan de corrección priorizado con ayuda de un modelo de lenguaje.

> Proyecto de la asignatura **Proyectos de Ciberseguridad** — Grado en Ingeniería de Software, mención en Ciberseguridad (U-TAD), curso 2026/2027.
> Autor: Arturo Igor Diez Cardenas.

## ⚠️ Uso responsable

Esta herramienta **solo debe utilizarse contra sitios propios o sobre los que se tenga autorización expresa**.
- El **modo pasivo** (por defecto) solo realiza las peticiones que haría un navegador al visitar la URL.
- El **modo completo** (`--authorized`) envía peticiones adicionales a rutas concretas y exige confirmar que se dispone de autorización (art. 197 bis del Código Penal).

## Qué analiza

| # | Motor | Modo |
|---|---|---|
| 1 | Cabeceras de seguridad HTTP (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP) | Pasivo |
| 2 | Cookies (Secure, HttpOnly, SameSite, prefijos `__Host-` / `__Secure-`) | Pasivo |
| 3 | TLS y certificado (redirección a HTTPS, validez, caducidad, nombre del host, versiones de TLS) | Pasivo |
| 4 | Rutas y ficheros sensibles (`.env`, `.git/`, copias de seguridad, paneles, `robots.txt`, `security.txt`) | Completo |
| 5 | Superficie de contenido (SRI, contenido mixto, formularios HTTP, `noopener`) | Pasivo |
| 6 | Tecnologías y vulnerabilidades conocidas (fingerprinting + base local de CVE de NVD) | Pasivo |

Además: histórico en SQLite, comparación entre escaneos y exportación a PDF, HTML y JSON.

## Instalación (desarrollo)

Requiere Python 3.11 o superior.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -e ".[dev]"
```

## Uso previsto

```bash
escaner scan https://mi-sitio.es
escaner scan https://mi-sitio.es --authorized --profile tecnico
escaner history mi-sitio.es
escaner compare mi-sitio.es --last 2
escaner export 42 --format pdf
escaner ask 42 "¿Cómo activo HSTS en Nginx?"
```

## Estructura

```
escaner/
├── cli.py            # comandos scan, history, compare, export, ask
├── scanner.py        # orquestador del escaneo
├── validator.py      # normalización de URL y protección anti-SSRF
├── models.py         # ScanContext, Finding, ScanResult
├── scoring.py        # notas por categoría y nota global
├── storage.py        # acceso a SQLite (consultas parametrizadas)
├── acquisition/      # fetcher.py, tls_client.py
├── engines/          # headers, cookies, tls, paths, content, tech
├── rules/            # reglas de cada motor definidas como datos
├── cve/              # updater.py (descarga NVD), matcher.py
├── ai/               # sanitizer, prompts, report, ask, providers
└── reporting/        # plantillas Jinja2 y exportadores PDF/HTML/JSON
lab/                  # laboratorio de pruebas (Nginx/Apache en VM)
tests/                # pruebas unitarias y de integración
AI_USAGE.md           # registro del uso de IA durante el desarrollo
```

## Calidad

```bash
pytest                 # pruebas
ruff check .           # análisis estático
bandit -r escaner      # análisis de seguridad del código
pip-audit              # vulnerabilidades en dependencias
```

## Planificación

| Fecha | Hito |
|---|---|
| 28/09/2026 | Idea final (memoria de planteamiento) ✅ |
| 26/10/2026 | Núcleo funcional: adquisición, cabeceras, cookies, TLS, puntuación y CLI |
| 16/11/2026 | Control interno: seis motores, histórico e informe con IA |
| 30/11/2026 | Entrega final |

## Uso de IA en el desarrollo

El desarrollo se apoya en un agente de programación basado en IA y en un asistente conversacional, siguiendo un flujo con revisión manual de todo el código generado. Cada uso relevante queda registrado en [`AI_USAGE.md`](AI_USAGE.md) y los commits en los que ha intervenido la IA llevan la etiqueta `[IA]`.
