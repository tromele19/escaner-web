"""Reglas del motor de cookies (apartado 2.3 de la memoria)."""

from escaner.models import Category, Severity
from escaner.rules import Rule, register

C = Category.COOKIES
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"

register(
    Rule(
        "SESSION_COOKIE_NO_SECURE",
        C,
        Severity.HIGH,
        "Cookie de sesión sin Secure: puede viajar sin cifrar",
        MDN,
    ),
    Rule(
        "SESSION_COOKIE_NO_HTTPONLY",
        C,
        Severity.HIGH,
        "Cookie de sesión sin HttpOnly: accesible desde JavaScript (robo por XSS)",
        MDN,
    ),
    Rule(
        "SESSION_COOKIE_NO_SAMESITE",
        C,
        Severity.LOW,
        "Cookie de sesión sin SameSite explícito",
        MDN,
    ),
    Rule("COOKIE_NO_SECURE", C, Severity.LOW, "Cookie sin el atributo Secure", MDN),
    Rule(
        "COOKIE_SAMESITE_NONE_INSECURE",
        C,
        Severity.MEDIUM,
        "Cookie con SameSite=None sin Secure: los navegadores la rechazan",
        MDN,
    ),
    Rule(
        "COOKIE_SAMESITE_INVALID", C, Severity.LOW, "Cookie con un valor de SameSite no válido", MDN
    ),
    Rule(
        "COOKIE_PREFIX_INVALID",
        C,
        Severity.MEDIUM,
        "Cookie con prefijo __Host-/__Secure- que no cumple sus requisitos",
        MDN,
    ),
    Rule(
        "SESSION_COOKIE_HOST_PREFIX",
        C,
        Severity.INFO,
        "Cookie de sesión con prefijo __Host- (buena práctica)",
        MDN,
        bonus=5,
    ),
)
