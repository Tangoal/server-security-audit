#!/usr/bin/env bash
# Installe (ou réinstalle) le service et le timer d'audit sur CETTE machine.
#
# Le dépôt est partagé entre plusieurs serveurs : l'unité systemd ne peut donc
# pas être versionnée avec un chemin en dur, sinon chaque `git pull` écrase le
# chemin de la machine d'en face. Elle est générée ici, et n'existe que dans
# /etc/systemd/system — jamais dans le dépôt.
#
# Le script, son .env et ses rapports sont déployés HORS du dépôt (root-only),
# pas exécutés/lus depuis $SCRIPT_DIR : ce dossier appartient typiquement à un
# compte non-root (et peut être monté en écriture dans un conteneur exposé
# publiquement) — quiconque peut y écrire obtiendrait root à l'heure du timer
# sinon. Incident réel du 2026-09-21 : voir AGENTS.md § Sécurité du dispositif.
#
# Usage : sudo ./install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_DIR="/etc/systemd/system"
NAME="server-security-audit"
BIN_DEST="/usr/local/sbin/server-security-audit.sh"
CONF_DIR="/etc/server-security-audit"
ENV_DEST="$CONF_DIR/.env"
REPORTS_DEST="/var/lib/server-security-audit/reports"

if [ "$(id -u)" != "0" ]; then
  echo "ERREUR: à lancer avec sudo (déploie dans $UNIT_DIR, $CONF_DIR, /usr/local/sbin)." >&2
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

# --- Déploiement hors du dépôt ----------------------------------------------
install -o root -g root -m 750 "$SCRIPT_DIR/audit.sh" "$BIN_DEST"
install -d -o root -g root -m 700 "$CONF_DIR"
install -o root -g root -m 600 "$SCRIPT_DIR/.env" "$ENV_DEST"
# REPORTS_DIR du .env déployé doit pointer vers un dossier root-only,
# indépendamment de ce que dit le .env source dans le dépôt (qui peut très
# bien laisser la valeur vide, ou pointer dans le dépôt pour un usage local
# avant migration) : on l'impose ici à chaque install.
if grep -q '^REPORTS_DIR=' "$ENV_DEST"; then
  sed -i "s#^REPORTS_DIR=.*#REPORTS_DIR=$REPORTS_DEST#" "$ENV_DEST"
else
  printf '\nREPORTS_DIR=%s\n' "$REPORTS_DEST" >> "$ENV_DEST"
fi
install -d -o root -g root -m 750 "$REPORTS_DEST"

cat > "$UNIT_DIR/$NAME.service" <<EOF
[Unit]
Description=Audit de sécurité hebdomadaire du serveur
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
# Généré par install.sh — ne pas éditer à la main, toute modification est
# perdue à la prochaine installation. Le binaire, le .env et les rapports
# sont déployés hors du dépôt ($SCRIPT_DIR) — voir AGENTS.md § Sécurité du
# dispositif. Après tout \`git pull\` qui touche audit.sh ou .env, relancer
# \`sudo $SCRIPT_DIR/install.sh\` pour repropager la copie déployée.
User=root
Environment=AUDIT_ENV_FILE=$ENV_DEST
Environment=AUDIT_SOURCE_DIR=$SCRIPT_DIR
ExecStart=$BIN_DEST
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
echo "  binaire déployé : $BIN_DEST"
echo "  config déployée : $ENV_DEST"
echo "  rapports        : $REPORTS_DEST"
systemctl list-timers "$NAME.timer" --no-pager
echo
echo "Run immédiat (facultatif) : sudo systemctl start $NAME.service"
