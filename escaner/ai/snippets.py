"""Fragmentos de configuración revisados, por regla y servidor web.

La configuración que se propone en el plan NO la escribe el modelo: sale de
este catálogo fijo, revisado a mano. Así un modelo pequeño no puede inventar
una directiva incorrecta o peligrosa, y el resultado es reproducible. La IA
solo decide el orden y explica el porqué.
"""

from __future__ import annotations

HSTS = {
    "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
}
CSP = {
    "nginx": "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; "
    "frame-ancestors 'self'; base-uri 'self'\" always;",
    "apache": "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; "
    "frame-ancestors 'self'; base-uri 'self'\"",
}
SESSION_COOKIE = {
    "nginx": "# En la aplicación (PHP: php.ini)\nsession.cookie_secure = 1\n"
    "session.cookie_httponly = 1\nsession.cookie_samesite = Lax\n"
    "# o, como proxy (nginx 1.19.3+): proxy_cookie_flags ~ secure httponly samesite=lax;",
    "apache": "# En la aplicación (PHP: php.ini)\nsession.cookie_secure = 1\n"
    "session.cookie_httponly = 1\nsession.cookie_samesite = Lax\n"
    '# o en Apache: Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"',
}
REDIRECT_HTTPS = {
    "nginx": "server {\n    listen 80;\n    server_name _;\n    return 301 https://$host$request_uri;\n}",
    "apache": "RewriteEngine On\nRewriteCond %{HTTPS} off\n"
    "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
}
TLS_VERSIONS = {
    "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
    "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
}
DENY_PATHS = {
    "nginx": "location ~ /\\.(git|env|svn|ht) { deny all; return 404; }\n"
    "location ~* \\.(bak|old|orig|sql|zip|tar|gz|swp)$ { deny all; return 404; }",
    "apache": '<FilesMatch "^\\.(git|env|svn|ht)|\\.(bak|old|orig|sql|zip|tar|gz|swp)$">\n'
    "    Require all denied\n</FilesMatch>\nRedirectMatch 404 /\\.git",
}

SNIPPETS: dict[str, dict[str, str]] = {
    "HSTS_MISSING": HSTS,
    "HSTS_INVALID": HSTS,
    "HSTS_SHORT_MAX_AGE": HSTS,
    "HSTS_NO_SUBDOMAINS": HSTS,
    "CSP_MISSING": CSP,
    "CSP_NO_SCRIPT_SRC": CSP,
    "XFO_MISSING": {
        "nginx": 'add_header X-Frame-Options "SAMEORIGIN" always;',
        "apache": 'Header always set X-Frame-Options "SAMEORIGIN"',
    },
    "XCTO_MISSING": {
        "nginx": 'add_header X-Content-Type-Options "nosniff" always;',
        "apache": 'Header always set X-Content-Type-Options "nosniff"',
    },
    "REFERRER_POLICY_MISSING": {
        "nginx": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    },
    "PERMISSIONS_POLICY_MISSING": {
        "nginx": 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
        "apache": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
    },
    "XXSS_ENABLED": {
        "nginx": 'add_header X-XSS-Protection "0" always;',
        "apache": 'Header always set X-XSS-Protection "0"',
    },
    "SESSION_COOKIE_NO_SECURE": SESSION_COOKIE,
    "SESSION_COOKIE_NO_HTTPONLY": SESSION_COOKIE,
    "SESSION_COOKIE_NO_SAMESITE": SESSION_COOKIE,
    "TLS_NO_HTTPS_REDIRECT": REDIRECT_HTTPS,
    "TLS_V10_ENABLED": TLS_VERSIONS,
    "TLS_V11_ENABLED": TLS_VERSIONS,
    "TLS_NO_TLS12_OR_13": TLS_VERSIONS,
    "ENV_FILE_EXPOSED": DENY_PATHS,
    "GIT_REPO_EXPOSED": DENY_PATHS,
    "BACKUP_FILE_EXPOSED": DENY_PATHS,
    "DIRECTORY_LISTING": {"nginx": "autoindex off;", "apache": "Options -Indexes"},
    "TECH_VERSION_DISCLOSED": {
        "nginx": "server_tokens off;\n# PHP (php.ini): expose_php = Off",
        "apache": "ServerTokens Prod\nServerSignature Off\n# PHP (php.ini): expose_php = Off",
    },
}


def snippets_for(rule_ids: list[str], server: str) -> str:
    """Fragmentos (sin repetir) para los hallazgos indicados."""
    server = server if server in {"nginx", "apache"} else "nginx"
    out: list[str] = []
    for rid in rule_ids:
        text = SNIPPETS.get(rid, {}).get(server)
        if text and text not in out:
            out.append(text)
    return "\n".join(out)
