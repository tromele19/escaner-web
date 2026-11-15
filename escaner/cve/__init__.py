"""Base local de CVE descargada de la API de NVD.

Productos que la herramienta sabe reconocer: nombre para mostrar y sus
identificadores CPE 2.3 en NVD (fabricante, producto). Algunos tienen más de
uno porque NVD ha cambiado el fabricante con el tiempo (nginx pasó a F5).
"""

PRODUCTS: dict[str, tuple[str, list[tuple[str, str]]]] = {
    "nginx": ("nginx", [("f5", "nginx"), ("nginx", "nginx")]),
    "apache": ("Apache HTTP Server", [("apache", "http_server")]),
    "iis": ("Microsoft IIS", [("microsoft", "internet_information_services")]),
    "php": ("PHP", [("php", "php")]),
    "openssl": ("OpenSSL", [("openssl", "openssl")]),
    "wordpress": ("WordPress", [("wordpress", "wordpress")]),
    "drupal": ("Drupal", [("drupal", "drupal")]),
    "joomla": ("Joomla!", [("joomla", "joomla\\!")]),
    "jquery": ("jQuery", [("jquery", "jquery")]),
}
