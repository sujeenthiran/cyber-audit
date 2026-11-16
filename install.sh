#!/usr/bin/env bash
# Installation en une commande : ./install.sh
set -e
cd "$(dirname "$0")"
if ! command -v docker >/dev/null; then
  echo "Docker est nécessaire : https://docs.docker.com/engine/install/"; exit 1
fi
if [ ! -f .env ]; then
  PW=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
  printf "AUDIT_PASSWORD=%s\nAUDIT_PORT=8090\n" "$PW" > .env
  chmod 600 .env
  echo "Mot de passe généré : $PW  (dans le fichier .env)"
fi
docker compose up -d --build
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "  CYBER AUDIT est prêt : http://${IP:-127.0.0.1}:$(grep AUDIT_PORT .env | cut -d= -f2)"
echo ""
