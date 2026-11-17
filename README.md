# Escáner de Seguridad Web con IA

Herramienta de línea de comandos en Python que audita la **configuración de seguridad** de un sitio web a partir de su URL, calcula una nota de la **A a la F** y genera un informe explicativo y un plan de corrección priorizado con ayuda de un modelo de lenguaje que se ejecuta en local.

> Proyecto de la asignatura **Proyectos de Ciberseguridad**. Grado en Ingeniería de Software, mención en Ciberseguridad (U-TAD), curso 2026/2027.
> Autor: Arturo Igor Diez Cardenas.

## Índice

1. [Uso responsable](#uso-responsable)
2. [Qué analiza](#qué-analiza)
3. [Instalación](#instalación)
4. [Configurar la IA (opcional)](#configurar-la-ia-opcional)
5. [Manual de uso](#manual-de-uso)
6. [Cómo se calcula la nota](#cómo-se-calcula-la-nota)
7. [Laboratorio y validación](#laboratorio-y-validación)
8. [Datos y privacidad](#datos-y-privacidad)
9. [Medidas de seguridad de la propia herramienta](#medidas-de-seguridad-de-la-propia-herramienta)
10. [Limitaciones conocidas](#limitaciones-conocidas)
11. [Solución de problemas](#solución-de-problemas)
12. [Desarrollo](#desarrollo)

## Uso responsable

Esta herramienta **solo debe utilizarse contra sitios propios o sobre los que se tenga autorización expresa**.

- El **modo pasivo** (por defecto) solo hace las peticiones que haría un navegador al visitar la URL, más las conexiones TLS normales para comprobar el certificado y las versiones aceptadas.
- El **modo completo** (`--authorized`) pide además rutas concretas (`/.env`, `/.git/HEAD`, copias de seguridad, paneles...). Exige confirmar que se tiene autorización: acceder a ficheros expuestos de un sistema ajeno puede ser delito (art. 197 bis del Código Penal).

## Qué analiza

| # | Motor | Modo | Reglas |
|---|---|---|---|
| 1 | **TLS y certificado**: HTTPS, redirección HTTP→HTTPS, validez, caducidad, nombre del host, autoridad, tamaño de clave, firma, TLS 1.0/1.1/1.2/1.3 | Pasivo | 14 |
| 2 | **Cabeceras de seguridad**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP, cabeceras obsoletas | Pasivo | 26 |
| 3 | **Cookies**: Secure, HttpOnly, SameSite, prefijos `__Host-` y `__Secure-` | Pasivo | 8 |
| 4 | **Tecnologías y CVE**: versión anunciada de Nginx, Apache, PHP, WordPress, jQuery... cruzada con una base local de CVE de NVD | Pasivo | 5 |
| 5 | **Contenido**: contenido mixto, formularios por HTTP, scripts y CSS de terceros sin SRI, `target="_blank"` sin `noopener` | Pasivo | 7 |
| 6 | **Rutas sensibles**: `.env`, `.git/`, copias de seguridad, listado de directorios, paneles de administración, `robots.txt`, `security.txt` | Completo | 8 |

Además: histórico en SQLite, comparación entre escaneos, informe y plan de remediación con IA, modo «pregunta al informe» y exportación a HTML, PDF y JSON.

## Instalación

### Requisitos

- Python **3.11 o superior** (probado con 3.11, 3.13 y 3.14 en Linux y Windows).
- Git.
- Opcional: [Ollama](https://ollama.com) para el informe con IA (ver más abajo).

### Linux (Kali, Debian, Ubuntu)

```bash
git clone https://github.com/tromele19/escaner-web.git
cd escaner-web
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[pdf]"          # «pdf» añade el motor para exportar a PDF
escaner version
```

### Windows (PowerShell)

```powershell
git clone https://github.com/tromele19/escaner-web.git
cd escaner-web
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[pdf]"
escaner version
```

Cada vez que se abra una terminal nueva hay que volver a activar el entorno virtual (`source .venv/bin/activate` o `.venv\Scripts\Activate.ps1`).

### Base de vulnerabilidades (CVE)

El motor de tecnologías cruza las versiones detectadas con una base local de CVE descargada de la API de NVD. Hay que descargarla una vez y actualizarla de vez en cuando:

```bash
escaner update-cve
```

Tarda unos minutos (NVD limita las peticiones sin clave; con una clave gratuita en `NVD_API_KEY` es más rápido). Si NVD falla, reintenta con espera creciente y guarda lo que haya podido descargar. Sin esta base el escáner funciona igual, pero avisa de que no ha podido comprobar las CVE.

## Configurar la IA (opcional)

La IA **solo** se usa en los comandos `report` y `ask`. Escanear, puntuar y exportar funciona sin ella.

### Opción por defecto: modelo local con Ollama

Ningún dato sale del equipo.

1. Instalar Ollama y descargar el modelo (se ha elegido uno pequeño, de 1,9 GB, para que funcione en un portátil normal):
   ```bash
   ollama pull qwen2.5:3b
   ```
2. Crear el fichero de configuración a partir del ejemplo y rellenarlo:
   ```bash
   cp .env.example .env
   ```
   ```ini
   ESCANER_AI_PROVIDER=ollama
   ESCANER_OLLAMA_URL=http://localhost:11434
   ESCANER_OLLAMA_MODEL=qwen2.5:3b
   ```
   El fichero `.env` está en `.gitignore` y **nunca** se sube al repositorio.

**Ollama en el anfitrión y el escáner en una máquina virtual.** Es la configuración usada en el desarrollo: Ollama en Windows y la herramienta en una VM Kali de VirtualBox.

- Se añade a la VM un segundo adaptador de red de tipo **«solo-anfitrión»**. Desde la VM, el anfitrión es siempre `192.168.56.1`, en cualquier red (casa, universidad...).
- En Windows, Ollama tiene que escuchar en la red (variable de entorno `OLLAMA_HOST=0.0.0.0`). Su regla del firewall se limita a esa red interna, para que Ollama no sea accesible desde la red local:
  ```powershell
  Get-NetFirewallRule -DisplayName "ollama.exe" | Set-NetFirewallRule -EdgeTraversalPolicy Block -RemoteAddress 192.168.56.0/24
  ```
- En el `.env` de la VM: `ESCANER_OLLAMA_URL=http://192.168.56.1:11434`.
- Para comprobar la conexión: `curl -s http://192.168.56.1:11434/api/tags` tiene que devolver el modelo.

### Alternativa: API compatible con OpenAI

Para usar un servicio externo (por ejemplo, con un nivel gratuito y el límite de gasto a 0):

```ini
ESCANER_AI_PROVIDER=api
ESCANER_API_BASE_URL=https://.../v1
ESCANER_API_KEY=...
ESCANER_API_MODEL=...
```

En ese caso el resultado saneado del escaneo (ver [Datos y privacidad](#datos-y-privacidad)) se envía a ese servicio.

## Manual de uso

Los comandos se pueden consultar en todo momento con `escaner --help` y `escaner <comando> --help`.

### 1. Escanear un sitio

```bash
escaner scan https://mi-sitio.es                  # modo pasivo
escaner scan mi-sitio.es                          # sin esquema se asume https
escaner scan https://mi-sitio.es --authorized     # modo completo (pide confirmación)
escaner scan https://mi-sitio.es --no-save        # no guardar en el histórico
escaner scan https://mi-sitio.es --json r.json    # guardar también el resultado en JSON
```

Muestra la nota global y la letra, la nota de cada categoría y la tabla de hallazgos ordenada por severidad, con su evidencia. Cada escaneo se guarda en el histórico con un **id**, que es el que usan los demás comandos.

### 2. Histórico y comparación

```bash
escaner history mi-sitio.es               # escaneos guardados (más reciente primero)
escaner compare mi-sitio.es               # compara los dos últimos
escaner compare mi-sitio.es --old 3 --new 7
```

`compare` muestra la variación de la nota y qué hallazgos se han **resuelto** y cuáles son **nuevos**. Sirve para comprobar que una corrección ha funcionado.

### 3. Informe y plan de remediación con IA

```bash
escaner report 7                          # perfil divulgativo (por defecto)
escaner report 7 --profile tecnico        # para administradores o desarrolladores
escaner report 7 --regenerate             # vuelve a generarlo aunque ya exista
```

El informe incluye:

- un resumen y un plan priorizado de acciones, redactados por la IA;
- la explicación de la nota, calculada por la herramienta (no por la IA);
- para cada acción, la configuración para Nginx o Apache, que sale de un catálogo de fragmentos revisados y no la escribe la IA;
- la lista de hallazgos de severidad media o superior que el plan de la IA no haya cubierto.

El informe se guarda y la siguiente vez se muestra sin volver a llamar al modelo. Si la IA no está disponible o responde algo no válido (tras un reintento), el comando lo indica y el resto de la herramienta sigue funcionando.

### 4. Preguntar sobre un informe

```bash
escaner ask 7 "¿Qué arreglo primero y por qué?"
escaner ask 7 "¿Cómo activo HSTS en Nginx?" --profile tecnico
```

Solo responde sobre ese escaneo. La pregunta se limita a 300 caracteres, y si la respuesta cita hallazgos que no están en el escaneo, se avisa.

### 5. Exportar

```bash
escaner export 7                          # HTML (por defecto): informe-mi-sitio.es-7.html
escaner export 7 -f pdf                   # PDF
escaner export 7 -f json -o r.json        # JSON para integrarlo en otros procesos
escaner export 7 --profile tecnico        # incluye el informe de IA técnico, si existe
escaner export 7 --no-ai                  # sin la sección de IA
```

El HTML es un único fichero autocontenido (no carga nada de Internet) que se puede abrir sin conexión o adjuntar. Si existe un informe de IA guardado, se incluye en una sección marcada como generada por IA.

### Flujo típico

```bash
escaner scan https://mi-sitio.es          # → id 7, nota D
escaner report 7                          # plan de corrección
# ... aplicar los cambios en el servidor ...
escaner scan https://mi-sitio.es          # → id 8
escaner compare mi-sitio.es               # D → B, 4 hallazgos resueltos
escaner export 8 -f pdf
```

## Cómo se calcula la nota

1. **Categorías.** Cada categoría empieza en 100 y cada hallazgo resta según su severidad: crítica −40, alta −25, media −10, baja −5, informativa 0. Algunas buenas prácticas (TLS 1.3, HSTS preload, `security.txt`...) suman un pequeño bonus, sin pasar de 100.
2. **Nota global.** Es la media ponderada de las categorías **evaluadas**: TLS 25 %, cabeceras 20 %, cookies 15 %, tecnologías 15 %, rutas 15 % y contenido 10 %. Una categoría que no se puede evaluar no cuenta: por ejemplo, rutas en modo pasivo, o cookies si el sitio no envía ninguna.
3. **Topes** (rúbrica 1.1):
   - con algún hallazgo de severidad **alta**, la nota máxima es **89 (B)**;
   - con algún hallazgo **crítico**, la nota máxima es **69 (D)**;
   - **sin HTTPS válido** (sin HTTPS, o con el certificado caducado, no confiable o de otro dominio), la nota máxima es **49 (F)**.
4. **Escala:** A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · E ≥ 50 · F < 50.

La nota la calcula siempre el código a partir de reglas fijas: **la IA no interviene en ella**. El tope por severidad alta se añadió en la rúbrica 1.1 tras la validación: un sitio sin HSTS sacaba una A por tener todo lo demás perfecto.

## Laboratorio y validación

- **Laboratorio** (`lab/`): sitios mal configurados a propósito, servidos por Nginx en la propia VM y accesibles solo desde `127.0.0.1`. Es el único sitio donde se usa el modo completo. Instalación y uso en [`lab/README.md`](lab/README.md). Como sus direcciones son privadas, se escanean con `--lab`:
  ```bash
  escaner scan https://inseguro.lab --lab
  escaner scan https://expuesto.lab --lab --authorized
  ```
- **Validación con sitios reales:** `python scripts/validar.py --observatory` escanea en modo pasivo los 32 sitios de [`validacion/sitios.txt`](validacion/sitios.txt) (incluidos 4 controles negativos de badssl.com, que deben salir con F), mide el tiempo y compara con Mozilla HTTP Observatory. Los resultados están en [`validacion/resultados.md`](validacion/resultados.md).

## Datos y privacidad

| Qué | Dónde | Notas |
|---|---|---|
| Histórico de escaneos e informes de IA | `~/.escaner-web/escaner.db` (SQLite) | Solo el resultado: nota, hallazgos y evidencias cortas. No se guarda el HTML ni las cabeceras completas. |
| Base de CVE | `~/.escaner-web/cve.json` | Se descarga de NVD. Los escaneos **no** consultan NVD, así que no se revela qué sitios se analizan. |
| Configuración y claves | `.env` | Nunca se sube al repositorio. |
| Informes exportados | Directorio actual (`informe-*`) | Ignorados por git. |

La carpeta de datos se puede cambiar con la variable `ESCANER_DATA_DIR`.

**Qué recibe el modelo de IA:** el dominio, las notas y la lista de hallazgos como identificadores de un catálogo cerrado (`HSTS_MISSING`...), con su título y severidad tomados del catálogo, más el producto y la versión numérica de las tecnologías detectadas. **No recibe** el HTML, las cabeceras, los valores de las cookies ni las evidencias tal cual.

## Medidas de seguridad de la propia herramienta

- **Anti-SSRF:** se rechazan las URL que apuntan a direcciones privadas, locales, de metadatos de la nube (`169.254.169.254`), multicast o IPv4 camufladas en IPv6, y se vuelve a validar el destino en **cada redirección**. Solo `--lab` permite direcciones privadas.
- **Límites:** tiempo máximo por petición, un máximo de 10 redirecciones con detección de bucles, 5 MB por respuesta y 64 KB por ruta sondeada; pausa entre peticiones en el modo completo.
- **Defensa frente a prompt injection:** el contenido del sitio nunca llega al modelo (ver el apartado anterior). La respuesta del modelo se valida (JSON con la estructura esperada, identificadores citados que existan en el escaneo, longitud limitada, sin caracteres de control) y lo que no cumple se descarta.
- **Salida segura:** en la terminal, el texto del sitio se muestra como texto literal, sin interpretar marcado ni secuencias de escape. En el HTML se escapa todo con Jinja2 y una Content-Security-Policy prohíbe scripts y recursos externos.
- **Base de datos:** todas las consultas son parametrizadas.

## Limitaciones conocidas

- Analiza la **configuración**, no busca vulnerabilidades en la lógica de la aplicación (inyecciones, autenticación...). No sustituye a una auditoría.
- Las CVE se basan en la versión **anunciada**: las distribuciones aplican parches sin cambiar el número, así que son posibles vulnerabilidades a verificar.
- Algunos sitios con protección anti-bots no responden a clientes que no son un navegador (en la validación, caixabank.es agotó el tiempo de espera).
- Las pruebas de TLS 1.0/1.1 dependen de que el OpenSSL local permita negociarlas; si no lo permite, se marcan como «no comprobado» y no penalizan.
- El modelo local de 3B parámetros comete errores de redacción, como contar mal los hallazgos o atribuir acciones a hallazgos que no cita. Por eso la nota, las cifras y la configuración no dependen de él.

## Solución de problemas

| Problema | Solución |
|---|---|
| `escaner: command not found` | Activar el entorno virtual: `source .venv/bin/activate`. |
| «No se puede resolver el host» | Comprobar el dominio; algunos solo existen con `www.` (por ejemplo, `www.seg-social.es`). |
| «apunta a una dirección no pública» | Es la protección anti-SSRF. Para el laboratorio propio, añadir `--lab`. |
| «Ollama no responde en ...» | Comprobar que Ollama está abierto y la URL del `.env`; probar con `curl -s <URL>/api/tags`. Desde una VM, usar la red solo-anfitrión (ver [Configurar la IA](#configurar-la-ia-opcional)). |
| «No hay informe de IA: el modelo no devolvió un informe válido» | Repetir con `--regenerate`; los modelos pequeños fallan a veces el formato. La nota y el export siguen disponibles. |
| «No se ha podido comprobar CVE» | Descargar la base: `escaner update-cve`. |
| `update-cve` da 503 o 429 | NVD está saturado; vuelve a intentarlo solo. Si persiste, repetir más tarde o usar `NVD_API_KEY`. |
| Exportar a PDF pide instalar un motor | `pip install -e ".[pdf]"`. |
| Los sitios `.lab` no responden | `sudo systemctl restart nginx` en la VM del laboratorio. |

## Desarrollo

```bash
pip install -e ".[dev,pdf]"
pytest                    # pruebas (sin red: DNS, HTTP, TLS e IA simulados)
ruff check .              # análisis estático
bandit -r escaner         # análisis de seguridad del código
pip-audit                 # vulnerabilidades en las dependencias
```

GitHub Actions ejecuta todo lo anterior en cada push y pull request, con Linux y Windows y con Python 3.11 y 3.14.

### Estructura

```
escaner/
├── cli.py            # comandos scan, history, compare, report, ask, export, update-cve
├── scanner.py        # orquestador del escaneo
├── validator.py      # normalización de URL y protección anti-SSRF
├── models.py         # ScanContext, Finding, ScanResult
├── scoring.py        # notas por categoría, nota global y topes
├── storage.py        # histórico en SQLite (consultas parametrizadas)
├── acquisition/      # fetcher (HTTP), tls_client, prober (rutas)
├── engines/          # tls, headers, cookies, tech, content, paths
├── rules/            # catálogo de reglas como datos
├── cve/              # fingerprint, updater (NVD), matcher
├── ai/               # sanitizer, prompts, providers, report, ask, facts, snippets
└── reporting/        # exportación JSON, HTML y PDF (plantilla Jinja2)
lab/                  # laboratorio de pruebas (Nginx en la VM)
scripts/validar.py    # validación contra sitios reales
validacion/           # lista de sitios y resultados
tests/                # pruebas unitarias
AI_USAGE.md           # registro del uso de IA durante el desarrollo
```

### Uso de IA en el desarrollo

El desarrollo se ha apoyado en un agente de programación basado en IA y en un asistente conversacional, con revisión manual de todo el código generado. Cada uso relevante queda registrado en [`AI_USAGE.md`](AI_USAGE.md), con los errores detectados y cómo se validó, y los commits en los que ha intervenido la IA llevan la etiqueta `[IA]`.
