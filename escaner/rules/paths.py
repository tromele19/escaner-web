"""Reglas del motor de rutas sensibles (apartado 2.3 de la memoria).

Además de las reglas, aquí está la lista CERRADA de rutas que se comprueban:
pocas y conocidas, sin fuerza bruta (uso responsable, RNF-08).
"""

from escaner.models import Category, Severity
from escaner.rules import Rule, register

P = Category.PATHS
OWASP_CONF = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"

register(
    Rule(
        "ENV_FILE_EXPOSED",
        P,
        Severity.CRITICAL,
        "Fichero .env accesible: puede contener contraseñas y claves",
        OWASP_CONF,
    ),
    Rule(
        "GIT_REPO_EXPOSED",
        P,
        Severity.CRITICAL,
        "Repositorio .git accesible: permite descargar el código fuente",
        OWASP_CONF,
    ),
    Rule(
        "BACKUP_FILE_EXPOSED",
        P,
        Severity.HIGH,
        "Copia de seguridad o fichero antiguo accesible",
        OWASP_CONF,
    ),
    Rule("DIRECTORY_LISTING", P, Severity.MEDIUM, "Listado de directorios activado", OWASP_CONF),
    Rule(
        "ADMIN_PANEL_EXPOSED",
        P,
        Severity.MEDIUM,
        "Panel de administración accesible públicamente",
        OWASP_CONF,
    ),
    Rule(
        "ROBOTS_REVEALS_PATHS",
        P,
        Severity.LOW,
        "robots.txt revela rutas sensibles",
        "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
    ),
    Rule(
        "SECURITY_TXT_MISSING",
        P,
        Severity.INFO,
        "No hay fichero security.txt para notificar vulnerabilidades",
        "https://www.rfc-editor.org/rfc/rfc9116",
    ),
    Rule(
        "SECURITY_TXT_PRESENT",
        P,
        Severity.INFO,
        "security.txt publicado (buena práctica)",
        "https://www.rfc-editor.org/rfc/rfc9116",
        bonus=5,
    ),
)

ENV_PATHS = ["/.env", "/.env.local", "/.env.production"]
GIT_PATHS = ["/.git/HEAD", "/.git/config"]
BACKUP_PATHS = [
    "/backup/",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db_backup.sql",
    "/backup/db_backup.sql",
    "/database.sql",
    "/dump.sql",
    "/index.html.bak",
    "/index.php.bak",
    "/index.php~",
    "/web.config.bak",
]
ADMIN_PATHS = ["/admin/", "/administrator/", "/wp-admin/", "/phpmyadmin/", "/login/"]
INFO_PATHS = ["/robots.txt", "/.well-known/security.txt", "/security.txt"]

ALL_PATHS = ENV_PATHS + GIT_PATHS + BACKUP_PATHS + ADMIN_PATHS + INFO_PATHS
