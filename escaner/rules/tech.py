"""Reglas del motor de tecnologías y vulnerabilidades conocidas (tabla 12)."""

from escaner.models import Category, Severity
from escaner.rules import Rule, register

T = Category.TECH
NVD = "https://nvd.nist.gov/"
OWASP_A06 = "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"

register(
    Rule(
        "TECH_VERSION_DISCLOSED",
        T,
        Severity.LOW,
        "El servidor anuncia la versión de su software",
        OWASP_A06,
    ),
    Rule(
        "TECH_CVE_HIGH",
        T,
        Severity.HIGH,
        "Versión con posibles vulnerabilidades conocidas graves (CVSS ≥ 7, a verificar)",
        NVD,
    ),
    Rule(
        "TECH_CVE_MEDIUM",
        T,
        Severity.MEDIUM,
        "Versión con posibles vulnerabilidades conocidas (CVSS 4–6,9, a verificar)",
        NVD,
    ),
    Rule(
        "TECH_CVE_LOW",
        T,
        Severity.LOW,
        "Versión con posibles vulnerabilidades conocidas leves (a verificar)",
        NVD,
    ),
    Rule(
        "TECH_CVE_DB_MISSING",
        T,
        Severity.INFO,
        "No hay base local de CVE: ejecuta «escaner update-cve»",
        NVD,
    ),
)
