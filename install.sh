#!/usr/bin/env bash
# Installe (ou réinstalle) le service et le timer d'audit sur CETTE machine.
#
# Le dépôt est partagé entre plusieurs serveurs : l'unité systemd ne peut donc
# pas être versionnée avec un chemin en dur, sinon chaque `git pull` écrase le
# chemin de la machine d'en face. Elle est générée ici à partir du chemin réel
# du script, et n'existe que dans /etc/systemd/system — jamais dans le dépôt.
#
# Usage : sudo ./install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_DIR="/etc/systemd/system"
NAME="server-security-audit"

if [ "$(id -u)" != "0" ]; then
  echo "ERREUR: à lancer avec sudo (l'unité s'installe dans $UNIT_DIR)." >&2
  exit 1
fi

if [ ! -f "$SCRIPT_DIR/.env" ]; then
  echo "ERREUR: $SCRIPT_DIR/.env absent." >&2
  echo "Copier .env.example en .env, le remplir, puis relancer." >&2
  exit 1
fi

# Le .env porte la clé d'API Resend. La documentation exige `chmod 600` depuis
# le début, mais rien ne le vérifiait : un .env laissé en 644 par un `cp` est
# lisible par tout compte de la machine, y compris depuis un conteneur qui
# monterait le dossier. On refuse plutôt que de corriger en silence : le fichier
# a peut-être aussi déjà été lu.
ENV_MODE="$(stat -c '%a' "$SCRIPT_DIR/.env")"
if [ "$ENV_MODE" != "600" ] && [ "$ENV_MODE" != "400" ]; then
  echo "ERREUR: $SCRIPT_DIR/.env est en mode $ENV_MODE (attendu 600)." >&2
  echo "Il contient la clé Resend. Corriger, puis relancer :" >&2
  echo "  chmod 600 $SCRIPT_DIR/.env" >&2
  echo "Si le fichier a pu être lu par un autre compte, révoquer la clé sur resend.com." >&2
  exit 1
fi

if [ ! -x "$SCRIPT_DIR/audit.sh" ]; then
  chmod +x "$SCRIPT_DIR/audit.sh"
fi

cat > "$UNIT_DIR/$NAME.service" <<EOF
[Unit]
Description=Audit de sécurité hebdomadaire du serveur
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
# Généré par install.sh — ne pas éditer à la main, toute modification est
# perdue à la prochaine installation. Le service tourne en root : les règles
# iptables, /etc/shadow, les sudoers et les journaux d'authentification ne sont
# pas lisibles autrement. L'appel à claude redescend sur CLAUDE_RUN_AS (.env).
User=root
ExecStart=$SCRIPT_DIR/audit.sh
TimeoutStartSec=30min
EOF

# Même horaire sur tous les serveurs : deux rapports de la même semaine
# décrivent le parc au même instant.
cat > "$UNIT_DIR/$NAME.timer" <<'EOF'
[Unit]
Description=Lance server-security-audit.service tous les lundis à 4h00 UTC

[Timer]
OnCalendar=Mon *-*-* 04:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "$NAME.timer"

echo "Installé depuis $SCRIPT_DIR"
systemctl list-timers "$NAME.timer" --no-pager
echo
echo "Run immédiat (facultatif) : sudo systemctl start $NAME.service"
