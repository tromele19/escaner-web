# Laboratorio de pruebas

Sitios web mal configurados **a propósito**, servidos por Nginx dentro de la propia VM Kali, para probar la herramienta sin tocar webs ajenas (apartado 10.2 de la memoria). Es imprescindible para el modo completo y el motor de rutas sensibles, que **nunca** se usan contra sitios de terceros.

## Instalación

Desde la raíz del repositorio, en la Kali:

```bash
sudo bash lab/setup.sh
```

El script instala Nginx, genera una autoridad de certificación propia («Escaner Lab CA») y la añade a la confianza de la Kali, copia los sitios a `/var/www/escaner-lab`, siembra los ficheros sensibles de `expuesto.lab`, añade los nombres `.lab` a `/etc/hosts` y arranca Nginx.

Para desinstalarlo: `sudo bash lab/setup.sh --remove`.

## Aislamiento

- Todos los sitios escuchan **solo en 127.0.0.1** y además deniegan cualquier otro origen (`allow 127.0.0.1; deny all;`), de modo que no son accesibles desde la red aunque la VM tenga un adaptador puente.
- Se desactiva el sitio por defecto de Nginx, que escucha en todas las interfaces.
- Los ficheros «sensibles» contienen datos ficticios.
- Las claves privadas se generan en la máquina y no se suben al repositorio (`lab/certs/` está en `.gitignore`).

## Sitios

| Sitio | Qué contiene | Resultado esperado |
|---|---|---|
| `correcto.lab` | HTTPS con certificado válido, redirección HTTP→HTTPS, todas las cabeceras, cookie `__Host-` correcta | A |
| `inseguro.lab` | Sin cabeceras de seguridad, `PHPSESSID` sin atributos, HTTP sin redirección, `X-Powered-By: PHP/7.4.3`, versión de Nginx anunciada, `WordPress 5.8` en el HTML | Nota baja; base para el motor de tecnologías |
| `expuesto.lab` | `.env`, `.git/HEAD`, `.git/config`, `backup/db_backup.sql`, `index.html.bak`, `/admin/`, `robots.txt` que revela rutas, listado de directorios | Base para el motor de rutas (modo completo) |
| `contenido.lab` | Script y imagen por HTTP (contenido mixto), scripts y CSS de terceros sin SRI, formulario de login a HTTP, enlace `target="_blank"` sin `noopener` | Base para el motor de contenido |
| `caducado.lab` | Certificado caducado firmado por la CA del laboratorio | F |

## Uso

Las direcciones del laboratorio son privadas (127.0.0.1), así que hay que usar siempre `--lab`:

```bash
escaner scan https://correcto.lab --lab
escaner scan https://inseguro.lab --lab
escaner scan http://inseguro.lab --lab
escaner scan https://caducado.lab --lab
escaner scan https://expuesto.lab --lab --authorized   # cuando exista el motor de rutas
```

## Sitios públicos de prueba

Subdominios de [badssl.com](https://badssl.com/) en modo pasivo: `expired`, `self-signed`, `wrong.host`. El de `tls-v1-0` usa el puerto 1010, que puede estar bloqueado según la red.
