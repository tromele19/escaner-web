# Laboratorio de pruebas

Entorno aislado en máquinas virtuales (VirtualBox + Linux con Nginx y Apache) para las pruebas activas de la herramienta (apartado 10.2 de la memoria). **Nunca se prueban el modo completo ni el motor de rutas contra sitios de terceros.**

## Sitios virtuales previstos

| Carpeta | Sitio | Qué contiene |
|---|---|---|
| `sites/correcto` | `correcto.lab` | Configuración correcta (debería sacar A) |
| `sites/inseguro` | `inseguro.lab` | Sin HSTS, cookies sin atributos, versión del servidor anunciada |
| `sites/expuesto` | `expuesto.lab` | Ficheros sensibles sembrados: `.env`, `.git/`, copias de seguridad |
| `sites/contenido` | `contenido.lab` | Contenido mixto, scripts de terceros sin SRI, formularios a HTTP |

- `nginx/` y `apache/`: ficheros de configuración de cada sitio virtual.
- `certs/`: certificados propios (autofirmado, caducado, nombre incorrecto). Las claves privadas no se suben al repositorio.

## Sitios públicos de prueba

Subdominios de [badssl.com](https://badssl.com/): `expired`, `self-signed`, `wrong.host`, `tls-v1-0` (puerto 1010), `mixed`.
