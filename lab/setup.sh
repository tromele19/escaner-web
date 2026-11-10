#!/usr/bin/env bash
# Monta el laboratorio del escáner en la Kali (Nginx + 5 sitios en 127.0.0.1).
#   sudo bash lab/setup.sh            -> instala o reinstala
#   sudo bash lab/setup.sh --remove   -> desinstala el laboratorio
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Ejecútalo con sudo: sudo bash lab/setup.sh"; exit 1; fi

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$LAB_DIR")"
WWW=/var/www/escaner-lab
CONF=/etc/nginx/sites-available/escaner-lab.conf
CA_SYS=/usr/local/share/ca-certificates/escaner-lab-ca.crt
HOSTS_LINE="127.0.0.1 correcto.lab inseguro.lab expuesto.lab contenido.lab caducado.lab"

if [[ "${1:-}" == "--remove" ]]; then
  rm -f /etc/nginx/sites-enabled/escaner-lab.conf "$CONF" "$CA_SYS"
  rm -rf "$WWW"
  sed -i '/escaner-lab/d;/correcto.lab inseguro.lab/d' /etc/hosts
  update-ca-certificates --fresh >/dev/null
  systemctl reload nginx 2>/dev/null || true
  echo "Laboratorio desinstalado."
  exit 0
fi

echo "[1/7] Instalando Nginx..."
apt-get install -y -q nginx >/dev/null

echo "[2/7] Generando certificados del laboratorio..."
PY="$REPO_DIR/.venv/bin/python"; [[ -x "$PY" ]] || PY=python3
"$PY" "$LAB_DIR/make_certs.py" "$LAB_DIR/certs"

echo "[3/7] Instalando la CA del laboratorio como autoridad de confianza de la Kali..."
cp "$LAB_DIR/certs/lab-ca.crt" "$CA_SYS"
# --fresh reconstruye el almacén entero: al reinstalar, la CA se regenera y
# la anterior no debe quedarse en el almacén.
update-ca-certificates --fresh >/dev/null 2>&1

echo "[4/7] Copiando los sitios y sembrando ficheros sensibles en expuesto.lab..."
rm -rf "$WWW"; mkdir -p "$WWW"
cp -r "$LAB_DIR/sites/." "$WWW/"
E="$WWW/expuesto"
cat > "$E/.env" <<'ENV'
# FICHERO DE PRUEBA DEL LABORATORIO: estos datos no son reales
APP_ENV=production
DB_HOST=127.0.0.1
DB_USER=admin
DB_PASSWORD=laboratorio-no-es-real
ENV
mkdir -p "$E/.git" "$E/backup"
echo "ref: refs/heads/main" > "$E/.git/HEAD"
printf '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://git.ejemplo-lab.test/empresa/web.git\n' > "$E/.git/config"
echo "-- copia de seguridad de prueba (sin datos reales)" > "$E/backup/db_backup.sql"
cp "$E/index.html" "$E/index.html.bak"
chown -R www-data:www-data "$WWW"

echo "[5/7] Configurando Nginx (solo 127.0.0.1)..."
sed "s#__LAB__#$LAB_DIR#g" "$LAB_DIR/nginx/escaner-lab.conf" > "$CONF"
ln -sf "$CONF" /etc/nginx/sites-enabled/escaner-lab.conf
# El sitio por defecto de Nginx escucha en todas las interfaces: se desactiva.
rm -f /etc/nginx/sites-enabled/default

echo "[6/7] Añadiendo los nombres .lab a /etc/hosts..."
grep -q "correcto.lab inseguro.lab" /etc/hosts || echo "$HOSTS_LINE  # escaner-lab" >> /etc/hosts

echo "[7/7] Arrancando Nginx..."
nginx -t
systemctl enable --now nginx >/dev/null 2>&1 || true
systemctl restart nginx  # restart (no reload) para que cargue los certificados nuevos
sleep 1

echo
echo "Comprobación rápida:"
for s in correcto inseguro expuesto contenido; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://$s.lab/" || true)
  echo "  https://$s.lab/  -> $code"
done
code=$(curl -s -o /dev/null -w '%{http_code}' https://caducado.lab/ || true)
echo "  https://caducado.lab/ -> $code (debe fallar: certificado caducado)"
echo
echo "Laboratorio listo. Escanéalo SIEMPRE con --lab, por ejemplo:"
echo "  escaner scan https://correcto.lab --lab"
