#!/usr/bin/env bash
# Audit de sécurité hebdomadaire d'un serveur, portable d'une machine à l'autre.
#
# Ce script ne connaît AUCUN nom de machine : tout ce qui est spécifique à un
# serveur (libellé, destinataire des alertes, documents de contexte, chemins
# sensibles) vit dans le `.env` posé à côté de lui. Le même fichier tourne à
# l'identique sur chaque serveur, avec son propre `.env`.
#
# Déroulé d'un run :
#   1. collecte de faits bruts en lecture seule (SSH, pare-feu, ports, groupes,
#      logs d'auth, mises à jour, cron, SUID/SGID, permissions des secrets) ;
#   2. envoi de ces faits à `claude -p` avec une checklist d'analyse, plus les
#      documents de contexte du serveur (CLAUDE.md / INFRA.md) s'ils existent,
#      pour ne pas signaler comme problème un choix d'architecture assumé ;
#   3. écriture du rapport dans `reports/<date>.md` (donc embarqué par la
#      sauvegarde quotidienne du dossier de travail, sans mécanisme dédié) ;
#   4. envoi SYSTÉMATIQUE du rapport par mail via Resend — y compris quand tout
#      va bien : l'absence de mail hebdomadaire signale une panne de l'audit
#      lui-même.
#
# Le script ne corrige rien : il constate et propose les commandes.
set -uo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${AUDIT_ENV_FILE:-$SCRIPT_DIR/.env}"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
else
  echo "ERREUR: fichier de configuration introuvable : $ENV_FILE" >&2
  echo "Copier .env.example en .env et le remplir." >&2
  exit 1
fi

SERVER_LABEL="${SERVER_LABEL:-$(hostname -s)}"
REPORTS_DIR="${REPORTS_DIR:-$SCRIPT_DIR/reports}"
REPORT_RETENTION="${REPORT_RETENTION:-60}"
AUDIT_TIMEOUT="${AUDIT_TIMEOUT:-900}"
# Modèle épinglé sur un identifiant complet, pas un alias : l'alias glisse d'une
# version à l'autre, et la rigueur de l'audit changerait sans que rien ne le
# signale. Laisser vide n'est PAS neutre — ce serait le modèle configuré dans la
# session interactive de CLAUDE_RUN_AS, donc un `/model` un soir change l'audit
# du lundi. Surchargeable dans le .env, jamais implicite.
AUDIT_MODEL="${AUDIT_MODEL:-claude-opus-5}"
CONTEXT_FILES="${CONTEXT_FILES:-}"
SENSITIVE_PATHS="${SENSITIVE_PATHS:-}"
CLOUDFLARED_CONFIG="${CLOUDFLARED_CONFIG:-/etc/cloudflared/config.yml}"
RESEND_API_KEY="${RESEND_API_KEY:-}"
ALERT_EMAIL_TO="${ALERT_EMAIL_TO:-}"
ALERT_EMAIL_FROM="${ALERT_EMAIL_FROM:-onboarding@resend.dev}"

DATE="$(date -u +%Y-%m-%d)"
REPORT="$REPORTS_DIR/$DATE.md"

# Le binaire `claude` n'est pas dans le PATH d'un service systemd (il vit dans
# le home de l'utilisateur). Chemin explicite possible via CLAUDE_BIN, sinon on
# le cherche là où l'installeur officiel le pose, y compris dans le home de
# l'utilisateur ciblé quand le service tourne en root.
resolve_claude() {
  if [ -n "${CLAUDE_BIN:-}" ]; then echo "$CLAUDE_BIN"; return; fi
  local candidate
  for candidate in \
      "$(command -v claude 2>/dev/null || true)" \
      "$HOME/.local/bin/claude" \
      "/usr/local/bin/claude"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then echo "$candidate"; return; fi
  done
  echo ""
}
CLAUDE="$(resolve_claude)"

# ---------------------------------------------------------------------------
# Privilèges
# ---------------------------------------------------------------------------
# La majorité des faits utiles (règles iptables, journaux d'authentification,
# sudoers, SUID sous /root) ne sont lisibles qu'en root. Le service systemd
# tourne donc en root ; lancé à la main sans droits, le script ne s'arrête pas,
# il note dans le rapport que la collecte est partielle — un audit dégradé
# reste plus utile qu'un audit absent.
if [ "$(id -u)" = "0" ]; then
  SUDO=""
  PRIV_NOTE="complet (exécuté en root)"
elif sudo -n true 2>/dev/null; then
  SUDO="sudo -n"
  PRIV_NOTE="complet (sudo sans mot de passe)"
else
  SUDO=""
  PRIV_NOTE="PARTIEL — exécuté sans privilèges root : les sections marquées « permission refusée » n'ont pas pu être collectées, elles ne valent pas ✅"
fi

# ---------------------------------------------------------------------------
# Collecte des faits
# ---------------------------------------------------------------------------
FACTS="$(mktemp)"
PROMPT_FILE="$(mktemp)"
PAYLOAD="$(mktemp)"
RAW_OUTPUT="$(mktemp)"
# `$RAW_OUTPUT.err` est listé ici aussi : il n'était supprimé que sur le chemin
# nominal, et restait dans /tmp à chaque interruption avant la fin.
cleanup() { rm -f "$FACTS" "$PROMPT_FILE" "$PAYLOAD" "$RAW_OUTPUT" "$RAW_OUTPUT.err"; }
trap cleanup EXIT

# sec <titre> <commande...> — exécute la commande et range sa sortie dans un
# bloc de code titré. Une commande absente ou refusée n'interrompt jamais la
# collecte : elle laisse une trace explicite dans les faits.
#
# La troncature est ANNONCÉE dans le bloc. Couper à 20 000 octets en silence
# faisait conclure l'analyse sur des données amputées sans qu'elle puisse le
# savoir : un relevé coupé au milieu ressemble à un relevé complet.
SEC_MAX_BYTES=20000
sec() {
  local title="$1"; shift
  local buf size
  buf="$(mktemp)"
  "$@" > "$buf" 2>&1
  size="$(wc -c < "$buf")"
  {
    printf '\n### %s\n```\n' "$title"
    head -c "$SEC_MAX_BYTES" "$buf"
    if [ "$size" -gt "$SEC_MAX_BYTES" ]; then
      printf '\n[… RELEVÉ TRONQUÉ : %s octets sur %s. Les faits manquants ne valent pas absence de problème.]\n' \
        "$SEC_MAX_BYTES" "$size"
    fi
    printf '```\n'
  } >> "$FACTS"
  rm -f "$buf"
}

# Idem pour un enchaînement de commandes shell (pipes, boucles).
secsh() {
  local title="$1" script="$2"
  sec "$title" bash -c "$script"
}

log "=== audit sécurité $SERVER_LABEL — $DATE ==="
log "privilèges : $PRIV_NOTE"
log "collecte des faits..."

secsh "Identité de la machine" \
  'hostnamectl 2>/dev/null | grep -vi "machine id\|boot id"; grep PRETTY /etc/os-release; uptime'

# --- SSH -------------------------------------------------------------------
secsh "SSH — configuration effective (sshd -T)" \
  "$SUDO sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|kbdinteractiveauthentication|challengeresponseauthentication|maxauthtries|maxsessions|x11forwarding|allowtcpforwarding|clientaliveinterval|clientalivecountmax|logingracetime|allowusers|allowgroups|denyusers|usepam|logingracetime|permittunnel)' || echo '(sshd -T indisponible — voir les fichiers de configuration ci-dessous)'"

secsh "SSH — fichiers de configuration (lignes actives)" \
  'for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
     [ -f "$f" ] || continue
     echo "--- $f ($(stat -c "%a %U:%G" "$f")) ---"
     grep -vE "^\s*#|^\s*$" "$f"
   done'

# Les clés publiques ne sont jamais recopiées telles quelles : seules l'empreinte,
# la taille et le commentaire partent dans le prompt.
secsh "SSH — clés autorisées (empreintes, jamais les clés elles-mêmes)" \
  "getent passwd | awk -F: '\$3==0 || \$3>=1000 {print \$1\" \"\$6}' | while read -r u h; do
     for f in \"\$h/.ssh/authorized_keys\" \"\$h/.ssh/authorized_keys2\"; do
       [ -e \"\$f\" ] || continue
       echo \"--- \$u : \$f (\$(stat -c '%a %U:%G %s octets' \"\$f\" 2>/dev/null))\"
       $SUDO ssh-keygen -lf \"\$f\" 2>/dev/null || echo '  (illisible ou vide)'
     done
     [ -d \"\$h/.ssh\" ] && echo \"    dossier \$h/.ssh : \$($SUDO stat -c '%a %U:%G' \"\$h/.ssh\" 2>/dev/null)\"
   done"

secsh "SSH — clés privées présentes sur la machine (permissions)" \
  "getent passwd | awk -F: '\$3==0 || \$3>=1000 {print \$6}' | sort -u | while read -r h; do
     [ -d \"\$h/.ssh\" ] || continue
     $SUDO find \"\$h/.ssh\" -maxdepth 1 -type f ! -name '*.pub' ! -name 'known_hosts*' ! -name 'authorized_keys*' ! -name 'config' \
       -printf '%M %u:%g %p\n' 2>/dev/null
   done"

# --- Comptes et privilèges -------------------------------------------------
secsh "Comptes utilisateurs (root + UID >= 1000)" \
  "getent passwd | awk -F: '\$3==0 || \$3>=1000 {printf \"%-16s uid=%-6s shell=%s home=%s\n\", \$1, \$3, \$7, \$6}'"

secsh "Groupes à risque (docker, lxd, sudo, adm, root)" \
  'getent group docker lxd lxc sudo admin wheel adm root 2>/dev/null'

secsh "Comptes sans mot de passe / verrouillage" \
  "$SUDO awk -F: '(\$2==\"\" ){print \$1\" : MOT DE PASSE VIDE\"} (\$2 ~ /^\\\$/){print \$1\" : mot de passe défini\"}' /etc/shadow 2>/dev/null || echo '(permission refusée sur /etc/shadow)'"

secsh "Règles sudo (NOPASSWD, ALL)" \
  "$SUDO grep -rhvE '^\s*#|^\s*$' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo '(permission refusée sur /etc/sudoers)'"

# --- Pare-feu et exposition réseau -----------------------------------------
secsh "Pare-feu — ufw" \
  "command -v ufw >/dev/null 2>&1 && { $SUDO ufw status verbose 2>&1 || echo '(permission refusée)'; } || echo '(ufw non installé)'"

# Les déclarations de chaînes (`-N`) sont retirées : seules les règles
# effectives comptent, et elles seules doivent tenir dans la limite de lignes.
secsh "Pare-feu — chaînes iptables filter (règles, hors déclarations)" \
  "$SUDO iptables -S 2>&1 | grep -v '^-N ' | head -n 150 || echo '(permission refusée)'"

secsh "Pare-feu — chaîne DOCKER-USER (contournement de ufw par Docker)" \
  "$SUDO iptables -S DOCKER-USER 2>&1 || echo '(chaîne absente ou permission refusée)'"

secsh "Pare-feu — redirections NAT publiées par Docker" \
  "$SUDO iptables -t nat -S DOCKER 2>&1 | head -n 60 || echo '(permission refusée)'"

# --- Exposition publique réelle --------------------------------------------
# Le pare-feu ne dit PAS ce qui est exposé sur Internet. Sur une machine
# derrière un tunnel Cloudflare, ufw peut légitimement tout refuser en entrée
# pendant que vingt hostnames sont publiés vers Traefik : la surface publique
# est décrite par la configuration du tunnel et par les routers Traefik, pas
# par iptables. Sans ces relevés, un ingress ajouté sans authentification est
# invisible pour l'audit.
#
# Aucun secret ne sort : on lit les hostnames et les cibles, jamais le fichier
# de credentials du tunnel (`<uuid>.json`), et le contenu de la configuration
# dynamique de Traefik est filtré par liste blanche (voir plus bas).
secsh "Exposition — dossier cloudflared (modes, fichiers résiduels)" \
  "[ -d \"\$(dirname '$CLOUDFLARED_CONFIG')\" ] \
     && $SUDO ls -l \"\$(dirname '$CLOUDFLARED_CONFIG')\" 2>&1 \
     || echo '(cloudflared absent de cette machine)'"

secsh "Exposition — hostnames publiés par le tunnel Cloudflare" \
  "if [ -f '$CLOUDFLARED_CONFIG' ]; then
     echo \"--- $CLOUDFLARED_CONFIG (\$($SUDO stat -c '%a %U:%G' '$CLOUDFLARED_CONFIG' 2>/dev/null)) ---\"
     $SUDO grep -nE '^[[:space:]]*(-[[:space:]]*)?(hostname|service|path|originRequest|noTLSVerify|httpHostHeader|access|audTag|warp-routing|enabled):' '$CLOUDFLARED_CONFIG' 2>/dev/null
     echo \"total : \$($SUDO grep -cE '^[[:space:]]*-?[[:space:]]*hostname:' '$CLOUDFLARED_CONFIG' 2>/dev/null) hostname(s) publié(s)\"
   else
     echo '(pas de configuration cloudflared : $CLOUDFLARED_CONFIG absent)'
   fi"

# Un router sans middleware est écrit explicitement « middlewares=(AUCUN) » :
# dans un dump de labels, l'absence d'authentification ne se voit pas, elle ne
# produit aucune ligne — et c'est précisément ce qu'il faut repérer.
secsh "Exposition — routers Traefik déclarés par les conteneurs" \
  "command -v docker >/dev/null 2>&1 || { echo '(docker indisponible)'; exit 0; }
   docker ps -q 2>/dev/null | while read -r c; do
     name=\$(docker inspect --format '{{.Name}}' \"\$c\" 2>/dev/null); name=\${name#/}
     labels=\$(docker inspect --format '{{range \$k,\$v := .Config.Labels}}{{\$k}}={{\$v}}
{{end}}' \"\$c\" 2>/dev/null | grep -i '^traefik')
     [ -n \"\$labels\" ] || continue
     echo \"--- \$name ---\"
     echo \"\$labels\" | grep -oE '^traefik\.http\.routers\.[^.]+' | sort -u | while read -r r; do
       rn=\${r##*.}
       rule=\$(echo \"\$labels\" | grep -E \"^\$r\.rule=\" | cut -d= -f2-)
       ep=\$(echo \"\$labels\" | grep -E \"^\$r\.entrypoints=\" | cut -d= -f2-)
       mw=\$(echo \"\$labels\" | grep -E \"^\$r\.middlewares=\" | cut -d= -f2-)
       tls=\$(echo \"\$labels\" | grep -E \"^\$r\.tls\" | head -n1 | cut -d= -f2-)
       echo \"  router=\$rn entrypoints=\${ep:-(defaut)} middlewares=\${mw:-(AUCUN)} tls=\${tls:-(non)} rule=\${rule:-(?)}\"
     done
     echo \"\$labels\" | grep -E '^traefik\.http\.services\..*\.loadbalancer\.server\.port=' | sed 's/^/  /'
     echo \"\$labels\" | grep -E '^traefik\.(enable|docker\.network)=' | sed 's/^/  /'
   done"

# Le provider « file » de Traefik définit des middlewares hors des conteneurs :
# une authentification peut vivre là, ou en être absente. Le contenu est extrait
# par LISTE BLANCHE (clés de structure et clés sûres) — ces fichiers portent des
# empreintes de mots de passe basicAuth, qui ne doivent jamais quitter la
# machine. Une ligne de valeur non listée n'est pas affichée.
secsh "Exposition — configuration dynamique Traefik (structure seule, valeurs masquées)" \
  "command -v docker >/dev/null 2>&1 || { echo '(docker indisponible)'; exit 0; }
   dirs=\$(docker ps -q 2>/dev/null | while read -r c; do
     docker inspect --format '{{range .HostConfig.Binds}}{{.}}
{{end}}' \"\$c\" 2>/dev/null | grep -i 'traefik' | cut -d: -f1
   done | sort -u)
   [ -n \"\$dirs\" ] || { echo '(aucun montage Traefik depuis l hote)'; exit 0; }
   for d in \$dirs; do
     [ -d \"\$d\" ] || continue
     echo \"--- \$d ---\"
     $SUDO find \"\$d\" -maxdepth 2 -type f -printf '%M %u:%g %s octets %p\n' 2>/dev/null | head -n 20
     $SUDO find \"\$d\" -maxdepth 2 -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.toml' \) 2>/dev/null | head -n 10 | while read -r f; do
       echo \"    structure de \$f :\"
       $SUDO grep -E '^[[:space:]]*[a-zA-Z0-9_.-]+:[[:space:]]*\$|^[[:space:]]*(rule|entrypoints|middlewares|service|scheme|address|permanent|insecureSkipVerify):' \"\$f\" 2>/dev/null | sed 's/^/      /'
     done
   done"

secsh "Ports en écoute (avec processus)" \
  "$SUDO ss -tulpenH 2>/dev/null | sed 's/\s\+/ /g' | sort -k5 | head -n 80 || ss -tuln"

secsh "Conteneurs Docker et ports publiés" \
  "command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}} | {{.Image}} | {{.Ports}}' 2>&1 || echo '(docker indisponible pour cet utilisateur)'"

secsh "Conteneurs Docker — privilèges et montages sensibles" \
  "command -v docker >/dev/null 2>&1 && docker ps -q 2>/dev/null | while read -r c; do
     docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}} user={{.Config.User}} binds={{range .HostConfig.Binds}}{{.}} {{end}}' \"\$c\" 2>/dev/null
   done | head -n 60 || echo '(docker indisponible)'"

# --- Journaux d'authentification -------------------------------------------
secsh "Authentification — échecs SSH des 7 derniers jours (volume)" \
  "{ $SUDO journalctl -u ssh -u sshd --since '7 days ago' --no-pager 2>/dev/null || $SUDO cat /var/log/auth.log 2>/dev/null; } \
     | grep -Eic 'failed password|invalid user|authentication failure' \
     | sed 's/^/tentatives en échec : /' || echo '(journaux inaccessibles)'"

secsh "Authentification — 15 IP sources les plus insistantes (7 jours)" \
  "{ $SUDO journalctl -u ssh -u sshd --since '7 days ago' --no-pager 2>/dev/null || $SUDO cat /var/log/auth.log 2>/dev/null; } \
     | grep -Ei 'failed password|invalid user' \
     | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -n 15 \
     || echo '(journaux inaccessibles)'"

secsh "Authentification — connexions réussies récentes" \
  "{ $SUDO journalctl -u ssh -u sshd --since '7 days ago' --no-pager 2>/dev/null | grep -i 'accepted' | tail -n 15; } ; last -n 10 2>/dev/null"

# Les échecs relevés plus haut disent qui n'est PAS entré. Ce relevé-ci dit qui
# a obtenu des privilèges, et c'est le signal qui compte : un compte créé ou un
# sudo accordé la semaine dernière n'apparaissait nulle part dans l'audit.
# Chaque ligne est coupée à 200 caractères. `sudo` recopie la ligne de commande
# complète dans le journal : une seule invocation portant un gros argument (le
# prompt d'un run précédent, par exemple) produit une ligne de dizaines de
# milliers de caractères, qui gonflerait les faits et réinjecterait du contenu
# arbitraire dans le prompt de l'analyse. Seul le début de la commande importe.
secsh "Élévations de privilèges et créations de comptes (7 jours)" \
  "logs=\$({ $SUDO journalctl --since '7 days ago' --no-pager 2>/dev/null || $SUDO cat /var/log/auth.log 2>/dev/null; } | cut -c1-200)
   [ -n \"\$logs\" ] || { echo '(journaux inaccessibles)'; exit 0; }
   echo \"sudo réussis : \$(echo \"\$logs\" | grep -cE 'sudo(\[[0-9]+\])?:.*COMMAND=') — 20 derniers :\"
   echo \"\$logs\" | grep -E 'sudo(\[[0-9]+\])?:.*COMMAND=' | sed -E 's/^([A-Za-z]{3} [ 0-9]+ [0-9:]+).*sudo[^:]*: *([a-z0-9_-]+).*(COMMAND=.*)/  \1 \2 \3/' | tail -n 20
   echo '--- bascules su vers un autre compte (10 dernières) ---'
   echo \"\$logs\" | grep -E ' su(\[[0-9]+\])?: .*session opened' | tail -n 10 || true
   echo '--- créations / modifications de comptes et de groupes ---'
   echo \"\$logs\" | grep -iE '(useradd|userdel|usermod|groupadd|groupmod|gpasswd)(\[[0-9]+\])?:' | tail -n 20
   echo '(fin)'"

secsh "Authentification — fail2ban" \
  "command -v fail2ban-client >/dev/null 2>&1 && { $SUDO fail2ban-client status 2>&1; } || echo '(fail2ban non installé)'"

# --- Mises à jour ----------------------------------------------------------
secsh "Mises à jour en attente" \
  "/usr/lib/update-notifier/apt-check --human-readable 2>&1 || echo '(apt-check indisponible)'"

secsh "Paquets à mettre à jour (sécurité d'abord)" \
  "up=\$(apt list --upgradable 2>/dev/null | tail -n +2)
   echo \"total : \$(echo \"\$up\" | grep -c . ) paquet(s) — dont \$(echo \"\$up\" | grep -ci 'security') étiqueté(s) sécurité\"
   echo '--- sécurité ---'; echo \"\$up\" | grep -i 'security' | head -n 30
   echo '--- autres (extrait) ---'; echo \"\$up\" | grep -vi 'security' | head -n 20"

# Le noyau en cours d'exécution est le seul fait qui tranche entre « correctif
# noyau appliqué » et « correctif installé mais pas encore chargé » : un paquet
# à jour sur le disque ne protège de rien tant que la machine n'a pas redémarré.
secsh "Noyau — version en cours d'exécution vs noyaux installés" \
  "echo \"en cours d execution : \$(uname -r)  (\$(uptime -p 2>/dev/null | sed 's/^up /machine démarrée depuis /'))\"
   echo '--- noyaux installés (état ii uniquement) ---'
   dpkg -l 'linux-image-*' 2>/dev/null | awk '\$1==\"ii\" && \$2 !~ /^linux-image-(fb-)?generic\$/ {print \$2\" \"\$3}' | sort | tail -n 6 \
     || echo '(dpkg indisponible)'"

secsh "Redémarrage requis / mises à jour automatiques" \
  "[ -f /var/run/reboot-required ] && { echo 'REDÉMARRAGE REQUIS :'; cat /var/run/reboot-required.pkgs 2>/dev/null | head -n 20; } || echo 'pas de redémarrage requis'
   echo \"unattended-upgrades : \$(systemctl is-enabled unattended-upgrades 2>/dev/null || echo absent) / \$(systemctl is-active unattended-upgrades 2>/dev/null || echo inactif)\"
   $SUDO tail -n 5 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null"

# --- Tâches planifiées -----------------------------------------------------
secsh "Tâches cron des utilisateurs" \
  "getent passwd | awk -F: '\$3==0 || \$3>=1000 {print \$1}' | while read -r u; do
     out=\$($SUDO crontab -l -u \"\$u\" 2>/dev/null | grep -vE '^\s*#|^\s*$')
     [ -n \"\$out\" ] && { echo \"--- \$u ---\"; echo \"\$out\"; }
   done; echo '(fin)'"

secsh "Cron système" \
  "grep -rhvE '^\s*#|^\s*\$' /etc/crontab /etc/cron.d/ 2>/dev/null | head -n 40; ls /etc/cron.hourly /etc/cron.daily /etc/cron.weekly 2>/dev/null"

secsh "Timers systemd actifs" \
  "systemctl list-timers --all --no-pager 2>/dev/null | head -n 30"

# --- SUID / SGID -----------------------------------------------------------
# Les couches d'images de conteneurs et les snaps contiennent normalement des
# binaires SUID (leur propre /usr/bin/su, passwd…) : les lister noierait les
# vrais SUID de l'hôte, qui sont les seuls exploitables directement.
secsh "Fichiers SUID/SGID de l'hôte (hors couches de conteneurs et snaps)" \
  "$SUDO find / -xdev \( -path /var/lib/docker -o -path /var/lib/containerd -o -path /snap -o -path /var/snap -o -path /var/lib/lxd -o -path /var/lib/lxcfs \) -prune -o \
     \( -perm -4000 -o -perm -2000 \) -type f -printf '%M %u:%g %p\n' 2>/dev/null | sort -k3 | head -n 120 || echo '(recherche impossible sans privilèges)'"

# --- Permissions des fichiers sensibles ------------------------------------
# Les chemins scrutés viennent du .env : ce sont eux qui portent les secrets du
# serveur (.env applicatifs, jetons d'API, clés). On regarde les PERMISSIONS,
# jamais le contenu — rien de secret ne doit partir dans le prompt ni le mail.
#
# Le jeu de motifs est défini UNE fois et réutilisé par les deux relevés
# ci-dessous : deux listes de motifs différentes produisaient un inventaire et
# une liste « lisible par tous » incohérents entre eux (un `.env.production`
# présent dans l'un, absent de l'autre), ce qui rend le rapport indécidable.
SENSITIVE_FIND_EXPR="\( -name '.env' -o -name '.env.*' -o -name '*.key' -o -name '*.pem' -o -name '*credentials*' -o -name '*token*' -o -name '*.secret' -o -name 'id_*' \) \
  ! -name '*.example' ! -name '*.pub' ! -path '*/node_modules/*' ! -path '*/.git/*'"

secsh "Permissions des fichiers sensibles (contenu jamais lu)" \
  "IFS=',' read -ra paths <<< \"$SENSITIVE_PATHS\"
   for p in \"\${paths[@]}\"; do
     p=\$(echo \"\$p\" | xargs); [ -n \"\$p\" ] || continue
     [ -e \"\$p\" ] || { echo \"(absent : \$p)\"; continue; }
     echo \"--- \$p ---\"
     $SUDO find \"\$p\" -maxdepth 4 $SENSITIVE_FIND_EXPR \
       -type f -printf '%M %u:%g %p\n' 2>/dev/null | head -n 60
   done"

secsh "Fichiers sensibles lisibles par tout le monde (à corriger en priorité)" \
  "IFS=',' read -ra paths <<< \"$SENSITIVE_PATHS\"
   for p in \"\${paths[@]}\"; do
     p=\$(echo \"\$p\" | xargs); [ -e \"\$p\" ] || continue
     $SUDO find \"\$p\" -maxdepth 4 $SENSITIVE_FIND_EXPR \
       -type f -perm /o=r -printf '%M %u:%g %p\n' 2>/dev/null
   done; echo '(fin)'"

secsh "Répertoires accessibles en écriture par tous dans les chemins sensibles" \
  "IFS=',' read -ra paths <<< \"$SENSITIVE_PATHS\"
   for p in \"\${paths[@]}\"; do
     p=\$(echo \"\$p\" | xargs); [ -d \"\$p\" ] || continue
     $SUDO find \"\$p\" -maxdepth 3 -type d -perm -o=w ! -path '*/node_modules/*' -printf '%M %u:%g %p\n' 2>/dev/null | head -n 20
   done; echo '(fin)'"

# --- Secrets versionnés par erreur -----------------------------------------
# Les permissions d'un `.env` ne protègent rien s'il est parti dans un dépôt
# git. On interroge l'index git (`ls-files`), pas le disque : un fichier
# ignoré correctement ne remonte pas, un fichier suivi remonte même s'il est
# aujourd'hui absent du disque. Toujours des NOMS de fichiers, jamais le contenu.
#
# Le motif porte sur le NOM DE FICHIER seul, pas sur le chemin : chercher
# « token » ou « credentials » n'importe où dans le chemin faisait remonter une
# migration `add_token_version.sql` et une documentation
# `ask-before-credentials.md`. Trois faux positifs sur quatre résultats, et une
# liste bruitée cesse d'être lue.
secsh "Secrets potentiellement versionnés dans un dépôt git" \
  "command -v git >/dev/null 2>&1 || { echo '(git indisponible)'; exit 0; }
   IFS=',' read -ra paths <<< \"$SENSITIVE_PATHS\"
   for p in \"\${paths[@]}\"; do
     p=\$(echo \"\$p\" | xargs); [ -d \"\$p\" ] || continue
     $SUDO find \"\$p\" -maxdepth 4 -type d -name .git ! -path '*/node_modules/*' 2>/dev/null | head -n 40 | while read -r g; do
       repo=\$(dirname \"\$g\")
       hits=\$(git -C \"\$repo\" ls-files 2>/dev/null | awk -F/ '
                { b = \$NF }
                b ~ /(\.example|\.sample|\.template|\.dist|\.pub)\$/ { next }
                b ~ /^\.env(\.[A-Za-z0-9_-]+)?\$/ ||
                b ~ /\.(key|pem|p12|pfx|secret|keystore)\$/ ||
                b ~ /^credentials(\.[A-Za-z]+)?\$/ ||
                b ~ /^[A-Za-z0-9_-]*(token|secret)s?\.(json|ya?ml|txt|env)\$/ ||
                b ~ /^id_(rsa|ed25519|ecdsa|dsa)\$/ { print }' | head -n 10)
       [ -n \"\$hits\" ] && { echo \"--- \$repo ---\"; echo \"\$hits\" | sed 's/^/  SUIVI PAR GIT : /'; }
     done
   done; echo '(fin)'"

# --- Intégrité de l'audit lui-même -----------------------------------------
# Ce script tourne en root depuis un dossier qui appartient à un utilisateur
# normal : qui peut écrire dans `audit.sh` obtient root à l'heure du timer.
# L'audit doit donc se surveiller lui-même — un fichier modifié hors dépôt ou
# un `.env` lisible par d'autres sont des faits au même titre que les autres.
secsh "Intégrité du dispositif d'audit (le script tourne en root)" \
  "echo '--- permissions ---'
   ls -ld '$SCRIPT_DIR' '$SCRIPT_DIR/audit.sh' '$SCRIPT_DIR/install.sh' '$ENV_FILE' 2>&1 | awk '{print \$1\" \"\$3\":\"\$4\" \"\$NF}'
   ls -l /etc/systemd/system/server-security-audit.* 2>/dev/null | awk '{print \$1\" \"\$3\":\"\$4\" \"\$NF}'
   echo '--- état du dépôt (une modification non commitée = code root altéré) ---'
   if git -C '$SCRIPT_DIR' rev-parse --git-dir >/dev/null 2>&1; then
     git -C '$SCRIPT_DIR' log -1 --format='dernier commit : %h %ad %an — %s' --date=short 2>/dev/null
     st=\$(git -C '$SCRIPT_DIR' status --porcelain 2>/dev/null | grep -vE '^\?\? reports/')
     [ -n \"\$st\" ] && { echo 'MODIFICATIONS NON COMMITÉES :'; echo \"\$st\"; } || echo 'arbre de travail propre'
   else
     echo '(pas un dépôt git)'
   fi"

# --- Intégrité système et signaux d'intrusion ------------------------------
# Quatre relevés bon marché qui répondent à « quelqu'un est-il passé ? » plutôt
# qu'à « la configuration est-elle correcte ? ». La cadence hebdomadaire leur
# convient : ils portent tous sur les 7 derniers jours ou sur un écart au
# paquet d'origine.
secsh "Intégrité — binaires divergents de leur paquet (debsums)" \
  "command -v debsums >/dev/null 2>&1 \
     && { $SUDO debsums -c 2>&1 | head -n 40; echo '(fin — aucune ligne au-dessus = tous les binaires conformes)'; } \
     || echo '(debsums non installé — contrôle impossible ; sudo apt install debsums pour l activer)'"

secsh "Intégrité — fichiers modifiés depuis 7 jours dans les chemins système" \
  "for d in /etc /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin /root; do
     [ -d \"\$d\" ] || continue
     out=\$($SUDO find \"\$d\" -xdev -type f -mtime -7 ! -path '/etc/mtab' ! -path '*/letsencrypt/*' \
             -printf '%TY-%Tm-%Td %M %u:%g %p\n' 2>/dev/null | sort | head -n 40)
     [ -n \"\$out\" ] && { echo \"--- \$d ---\"; echo \"\$out\"; }
   done; echo '(fin)'"

# Un exécutable supprimé du disque mais toujours en mémoire est le comportement
# normal d'un binaire mis à jour sans redémarrage du service — et aussi la
# signature classique d'une charge effacée après lancement. Le distinguo se
# fait sur le nom : c'est à l'analyse de trancher, pas à la collecte.
secsh "Intégrité — processus dont l'exécutable a été supprimé du disque" \
  "$SUDO ls -l /proc/*/exe 2>/dev/null | grep -i '(deleted)' \
     | sed -E 's#.*/proc/([0-9]+)/exe -> #pid \1 -> #' | head -n 30
   echo '(fin)'"

secsh "Intégrité — modules noyau chargés hors arborescence de la distribution" \
  "$SUDO lsmod 2>/dev/null | tail -n +2 | awk '{print \$1}' | while read -r m; do
     p=\$($SUDO modinfo -n \"\$m\" 2>/dev/null)
     case \"\$p\" in
       /lib/modules/*|/usr/lib/modules/*|'') ;;
       *) echo \"\$m -> \$p\" ;;
     esac
   done | head -n 20
   echo \"modules chargés : \$($SUDO lsmod 2>/dev/null | tail -n +2 | wc -l) — aucune ligne au-dessus = tous issus de la distribution\""

FACTS_SIZE="$(wc -c < "$FACTS")"
log "faits collectés : $FACTS_SIZE octets"

# ---------------------------------------------------------------------------
# Construction du prompt
# ---------------------------------------------------------------------------
# Les documents de contexte du serveur (CLAUDE.md, INFRA.md…) sont inclus
# seulement s'ils existent : une machine sans documentation produit un audit
# valable, juste sans le garde-fou « ce choix est assumé et documenté ».
CONTEXT_INCLUDED=()
{
  cat <<'PROMPT_HEAD'
Tu es un auditeur sécurité systèmes. On te donne l'état factuel d'un serveur
Linux, collecté en lecture seule juste avant cet appel. Rédige un rapport
d'audit en français, au format Markdown, à partir de CES FAITS UNIQUEMENT.

Règles :
- N'utilise aucun outil et ne cherche pas à lire de fichier : tout ce dont tu as
  besoin est dans ce message. Réponds directement par le rapport.
- N'invente rien. Si une section n'a pas pu être collectée (permission refusée,
  outil absent), dis-le explicitement et marque-la 🔍 Non vérifié — jamais ✅.
- Ne signale pas comme problème un choix d'architecture explicitement documenté
  dans la section « Contexte documenté du serveur » ci-dessous : mentionne-le
  comme assumé, et signale-le seulement si les faits montrent qu'il a dérivé de
  ce qui est documenté.
- Aucun secret ne doit apparaître dans le rapport (pas de clé, pas de jeton) :
  parle des permissions et des chemins, jamais du contenu.
- Tu constates et tu proposes : n'écris jamais que tu as corrigé quoi que ce
  soit. Les commandes de correction sont des suggestions à valider par un humain.

Format attendu, à respecter exactement :

# Audit de sécurité — <libellé du serveur> — <date>

## Synthèse
Un tableau : Domaine | Statut | Résumé en une ligne. Une ligne par domaine de la
checklist ci-dessous, dans l'ordre. Statuts possibles : ✅ OK, ⚠️ À corriger,
🚨 Critique, 🔍 Non vérifié.
Puis une ligne « **Bilan : N critique(s), N alerte(s), N non vérifié(s).** »

## 1. SSH
## 2. Pare-feu et filtrage réseau
## 3. Exposition publique (tunnel Cloudflare et Traefik)
## 4. Ports en écoute et conteneurs
## 5. Comptes et groupes à risque
## 6. Authentification, élévations de privilèges et brute-force
## 7. Mises à jour de sécurité
## 8. Tâches planifiées
## 9. Fichiers SUID/SGID
## 10. Permissions et exposition des secrets
## 11. Intégrité système et signaux d'intrusion

Dans chaque section : le statut, ce qui a été constaté (chiffres et valeurs
exactes tirés des faits), puis pour chaque problème le risque en une ou deux
phrases et un bloc ```bash``` avec la commande exacte de correction. Si une
section est saine, une ou deux phrases suffisent — mais indique quand même les
valeurs clés constatées, le rapport sert aussi de photo de l'état du serveur.

Précisions sur trois sections :
- Section 3 : un pare-feu qui refuse tout en entrée ne prouve RIEN sur la
  surface publique quand la machine est derrière un tunnel. Croise les
  hostnames publiés par le tunnel avec les routers Traefik : signale les
  hostnames publiés qui ne correspondent à aucun router, les routers dont la
  règle ne correspond à aucun hostname publié, et surtout tout router exposé
  sans middleware d'authentification (`middlewares=(AUCUN)`) donnant accès à
  une interface d'administration, une base ou un service interne.
- Section 10 : couvre à la fois les permissions des fichiers sensibles, les
  secrets suivis par git, et l'intégrité du dispositif d'audit lui-même (le
  script tourne en root : un fichier modifiable par d'autres, ou une
  modification non commitée, est un problème de sécurité en soi).
- Section 11 : distingue ce qui est attendu (binaire mis à jour sans
  redémarrage du service, fichier de configuration édité récemment et cohérent
  avec les autres faits) de ce qui ne l'est pas. Un contrôle indisponible
  (debsums absent) est 🔍 Non vérifié, jamais ✅.

## Priorités
Liste ordonnée des actions à mener, la plus urgente d'abord. Si rien n'est à
faire, écris « Aucune action requise. ».

Enfin, TERMINE ta réponse par ce bloc, seul sur ses lignes, sans rien après —
il est lu par un script, pas par un humain, et son absence fait considérer le
rapport comme tronqué :

```
AUDIT_SUMMARY crit=<nombre> warn=<nombre> unverified=<nombre>
```

Les trois nombres doivent être ceux du tableau de synthèse, comptés une seule
fois chacun.
PROMPT_HEAD

  if [ -n "$CONTEXT_FILES" ]; then
    IFS=',' read -ra ctx_paths <<< "$CONTEXT_FILES"
    for ctx in "${ctx_paths[@]}"; do
      ctx="$(echo "$ctx" | xargs)"
      [ -n "$ctx" ] || continue
      ctx="${ctx/#\~/$HOME}"
      if [ -f "$ctx" ]; then
        CONTEXT_INCLUDED+=("$ctx")
        printf '\n\n===== Contexte documenté du serveur : %s =====\n' "$ctx"
        cat "$ctx"
      fi
    done
  fi
  if [ ${#CONTEXT_INCLUDED[@]} -eq 0 ]; then
    printf '\n\n===== Contexte documenté du serveur =====\nAucun document de contexte sur cette machine : juge uniquement sur les faits.\n'
  fi

  printf '\n\n===== Métadonnées du run =====\n'
  printf 'Libellé du serveur : %s\nDate (UTC) : %s\nNiveau de privilèges de la collecte : %s\n' \
    "$SERVER_LABEL" "$DATE" "$PRIV_NOTE"

  printf '\n\n===== Faits collectés =====\n'
  cat "$FACTS"
} > "$PROMPT_FILE"

PROMPT_SIZE="$(wc -c < "$PROMPT_FILE")"
log "prompt construit : $PROMPT_SIZE octets (contexte : ${CONTEXT_INCLUDED[*]:-aucun})"

# Mise au point du prompt : `AUDIT_DRY_RUN=/chemin ./audit.sh` s'arrête ici et
# dépose le prompt complet, sans appeler claude ni envoyer de mail.
if [ -n "${AUDIT_DRY_RUN:-}" ]; then
  cp "$PROMPT_FILE" "$AUDIT_DRY_RUN"
  log "AUDIT_DRY_RUN : prompt déposé dans $AUDIT_DRY_RUN, arrêt avant l'analyse"
  exit 0
fi

# ---------------------------------------------------------------------------
# Analyse
# ---------------------------------------------------------------------------
mkdir -p "$REPORTS_DIR"
STATUS="ok"
FAILURE=""

if [ -z "$CLAUDE" ]; then
  STATUS="fail"
  FAILURE="binaire \`claude\` introuvable (définir CLAUDE_BIN dans $ENV_FILE)"
else
  # La session `claude` est authentifiée dans le home d'un utilisateur normal.
  # Le service tournant en root, on redescend sur cet utilisateur pour l'appel :
  # lancer claude avec HOME forcé laisserait des fichiers root dans son
  # ~/.claude, qui casseraient ses sessions interactives ensuite.
  #
  # `runuser` et pas `sudo` : sudo recopie la ligne de commande complète dans le
  # journal système, soit les dizaines de milliers de caractères du prompt à
  # chaque run. runuser ne journalise rien et n'a pas besoin de règle sudoers.
  CLAUDE_CMD=("$CLAUDE")
  if [ "$(id -u)" = "0" ] && [ -n "${CLAUDE_RUN_AS:-}" ] && [ "$CLAUDE_RUN_AS" != "root" ]; then
    RUN_HOME="$(getent passwd "$CLAUDE_RUN_AS" | cut -d: -f6)"
    if command -v runuser >/dev/null 2>&1; then
      CLAUDE_CMD=(runuser -u "$CLAUDE_RUN_AS" -- env "HOME=$RUN_HOME" "$CLAUDE")
    else
      CLAUDE_CMD=(sudo -n -u "$CLAUDE_RUN_AS" -H "$CLAUDE")
    fi
    log "appel de claude sous l'identité $CLAUDE_RUN_AS (HOME=$RUN_HOME)"
  fi
  # Le prompt DEMANDE de n'utiliser aucun outil ; ces deux options le rendent
  # impossible plutôt que souhaitable. `--allowed-tools ''` retire tous les
  # outils, `--strict-mcp-config` sans `--mcp-config` empêche le chargement des
  # serveurs MCP de l'utilisateur — ils coûteraient du contexte à chaque run et
  # rendraient l'analyse dépendante de la configuration interactive du moment.
  CLAUDE_ARGS=(-p "$(cat "$PROMPT_FILE")" --output-format text
               --model "$AUDIT_MODEL" --allowed-tools '' --strict-mcp-config)
  log "analyse via $CLAUDE (modèle $AUDIT_MODEL, timeout ${AUDIT_TIMEOUT}s)..."
  if timeout "$AUDIT_TIMEOUT" "${CLAUDE_CMD[@]}" "${CLAUDE_ARGS[@]}" > "$RAW_OUTPUT" 2>>"$RAW_OUTPUT.err"; then
    :
  else
    STATUS="fail"
    FAILURE="l'appel à claude a échoué ou dépassé ${AUDIT_TIMEOUT}s"
  fi
  # Une réponse trop courte est un rapport tronqué : on ne la publie pas comme
  # si l'audit avait abouti (l'absence de problème doit rester démontrée).
  if [ "$STATUS" = "ok" ] && [ "$(wc -c < "$RAW_OUTPUT")" -lt 500 ]; then
    STATUS="fail"
    FAILURE="réponse de claude trop courte ($(wc -c < "$RAW_OUTPUT") octets) — rapport probablement tronqué"
  fi
  # Le trailer AUDIT_SUMMARY est le dernier élément demandé : son absence
  # signifie que la réponse s'est arrêtée avant la fin. Sans ce contrôle, un
  # rapport coupé aux deux tiers ne contient aucun 🚨 et part avec un objet
  # « RAS » — le pire résultat possible pour un audit.
  if [ "$STATUS" = "ok" ] && ! grep -q '^AUDIT_SUMMARY ' "$RAW_OUTPUT"; then
    STATUS="fail"
    FAILURE="marqueur de fin AUDIT_SUMMARY absent — rapport incomplet, aucune conclusion exploitable"
  fi
  # Contrôle secondaire de forme : les 11 sections plus la synthèse et les
  # priorités. Un rapport hors format reste publié, mais il est signalé.
  SECTIONS_FOUND="$(grep -c '^## ' "$RAW_OUTPUT" || true)"
  if [ "$STATUS" = "ok" ] && [ "$SECTIONS_FOUND" -lt 13 ]; then
    log "ATTENTION: rapport hors format attendu ($SECTIONS_FOUND titres de niveau 2 sur 13 attendus)"
  fi
fi

# ---------------------------------------------------------------------------
# Rapport
# ---------------------------------------------------------------------------
# Le trailer AUDIT_SUMMARY a joué son rôle (preuve de complétude et décompte) :
# il est retiré du rapport publié, avec le bloc de code qui l'entoure et les
# lignes vides résiduelles. Le lecteur humain a déjà la ligne « Bilan » dans la
# synthèse ; deux formulations du même chiffre dans un même document finiraient
# par diverger.
strip_trailer() {
  awk '/^AUDIT_SUMMARY /{exit} {print}' "$1" \
    | awk '{l[n++]=$0}
           END{while(n>0 && (l[n-1] ~ /^[[:space:]]*$/ || l[n-1] ~ /^```[[:space:]]*$/)) n--;
               for(i=0;i<n;i++) print l[i]}'
}

{
  printf '<!-- généré par infra/server-security-audit/audit.sh le %s -->\n' "$(date -u '+%Y-%m-%d %H:%M UTC')"
  printf '<!-- serveur : %s · privilèges : %s · modèle : %s -->\n\n' "$SERVER_LABEL" "$PRIV_NOTE" "$AUDIT_MODEL"
  if [ "$STATUS" = "ok" ]; then
    strip_trailer "$RAW_OUTPUT"
  else
    printf '# Audit de sécurité — %s — %s\n\n## 🚨 L\x27audit n\x27a pas abouti\n\n' "$SERVER_LABEL" "$DATE"
    printf '**Cause :** %s\n\n' "$FAILURE"
    printf 'Aucune conclusion ne peut être tirée sur l\x27état de sécurité du serveur pour cette semaine.\n\n'
    printf 'Sortie brute de la commande :\n\n```\n%s\n```\n\n' "$(tail -c 3000 "$RAW_OUTPUT" 2>/dev/null; tail -c 2000 "$RAW_OUTPUT.err" 2>/dev/null)"
    printf 'Les faits collectés (%s octets) sont restés en local, relancer à la main :\n\n```bash\n%s\n```\n' \
      "$FACTS_SIZE" "$SCRIPT_DIR/audit.sh"
  fi
} > "$REPORT"
rm -f "$RAW_OUTPUT.err"
chmod 644 "$REPORT"
# Le service tourne en root dans un dossier qui appartient à un utilisateur :
# sans ça, les rapports lui deviennent illisibles en écriture et le dépôt se
# retrouve avec des fichiers root qu'il ne peut ni corriger ni supprimer.
if [ "$(id -u)" = "0" ] && [ -n "${CLAUDE_RUN_AS:-}" ] && [ "$CLAUDE_RUN_AS" != "root" ]; then
  chown "$CLAUDE_RUN_AS" "$REPORTS_DIR" "$REPORT" 2>/dev/null || true
fi
log "rapport écrit : $REPORT ($(wc -c < "$REPORT") octets)"

# Rotation : les rapports sont versionnés dans le dossier de travail et
# sauvegardés avec lui, inutile d'en garder un historique infini sur la machine.
find "$REPORTS_DIR" -maxdepth 1 -name '*.md' -type f -mtime "+$REPORT_RETENTION" -delete 2>/dev/null || true

# ---------------------------------------------------------------------------
# Envoi du rapport par mail (Resend) — systématique
# ---------------------------------------------------------------------------
# Le mail part quel que soit le verdict : il vaut aussi bilan de bonne santé de
# l'audit. Pas de mail le lundi = quelque chose ne tourne plus.
# Décompte, par ordre de fiabilité décroissante :
#   1. le trailer AUDIT_SUMMARY — champs nommés, un seul format possible ;
#   2. la ligne « Bilan » en prose — une regex sur du texte libre, ça se déforme ;
#   3. le comptage brut des symboles, qui SURESTIME (tableau de synthèse +
#      corps de section comptent chaque problème deux fois) mais ne peut pas
#      annoncer « RAS » à tort. Dans cet ordre, jamais l'inverse.
CRIT=0
WARN=0
SUMMARY_LINE="$(grep -m1 '^AUDIT_SUMMARY ' "$RAW_OUTPUT" 2>/dev/null || true)"
BILAN="$(grep -m1 -o 'Bilan *: *[0-9]* critique[^,]*, *[0-9]* alerte[^,]*' "$REPORT" || true)"
if [ -n "$SUMMARY_LINE" ]; then
  CRIT="$(echo "$SUMMARY_LINE" | grep -oE 'crit=[0-9]+' | cut -d= -f2)"
  WARN="$(echo "$SUMMARY_LINE" | grep -oE 'warn=[0-9]+' | cut -d= -f2)"
elif [ -n "$BILAN" ]; then
  CRIT="$(echo "$BILAN" | grep -oE '[0-9]+ critique' | grep -oE '^[0-9]+')"
  WARN="$(echo "$BILAN" | grep -oE '[0-9]+ alerte' | grep -oE '^[0-9]+')"
else
  CRIT="$(grep -c '🚨' "$REPORT" || true)"
  WARN="$(grep -c '⚠️' "$REPORT" || true)"
fi
CRIT="${CRIT:-0}"; WARN="${WARN:-0}"
# Le libellé du serveur ouvre l'objet : c'est la première chose lue dans une
# liste de messages, et c'est elle qui permet de filtrer par machine côté client
# mail quand le parc grandit. L'emoji final donne le verdict d'un coup d'œil,
# sans avoir à lire la fin de l'objet — souvent tronquée sur mobile.
if [ "$STATUS" != "ok" ]; then
  SUBJECT="[$SERVER_LABEL] [Audit-secu] — $DATE — ÉCHEC DE L'AUDIT ❌"
elif [ "$CRIT" -gt 0 ]; then
  SUBJECT="[$SERVER_LABEL] [Audit-secu] — $DATE — $CRIT point(s) critique(s), $WARN alerte(s) 🚨"
elif [ "$WARN" -gt 0 ]; then
  SUBJECT="[$SERVER_LABEL] [Audit-secu] — $DATE — $WARN alerte(s) ⚠️"
else
  SUBJECT="[$SERVER_LABEL] [Audit-secu] — $DATE — RAS ✅"
fi

send_report() {
  if [ -z "$RESEND_API_KEY" ] || [ -z "$ALERT_EMAIL_TO" ]; then
    log "ATTENTION: mail non envoyé (RESEND_API_KEY ou ALERT_EMAIL_TO absent de $ENV_FILE)"
    return 1
  fi
  # Le corps est le rapport intégral : construction du JSON en Python pour que
  # les accents, les guillemets et les blocs de code soient échappés proprement.
  RESEND_FROM="$ALERT_EMAIL_FROM" RESEND_TO="$ALERT_EMAIL_TO" \
  RESEND_SUBJECT="$SUBJECT" RESEND_BODY_FILE="$REPORT" RESEND_OUT="$PAYLOAD" \
  python3 - <<'PY' || return 1
import json, os
body = open(os.environ["RESEND_BODY_FILE"], encoding="utf-8", errors="replace").read()
json.dump({
    "from": os.environ["RESEND_FROM"],
    "to": [os.environ["RESEND_TO"]],
    "subject": os.environ["RESEND_SUBJECT"],
    "text": body,
}, open(os.environ["RESEND_OUT"], "w", encoding="utf-8"))
PY

  local http response
  response="$(mktemp)"
  http="$(curl -sS -o "$response" -w '%{http_code}' \
    -X POST https://api.resend.com/emails \
    -H "Authorization: Bearer $RESEND_API_KEY" \
    -H "Content-Type: application/json" \
    --data-binary "@$PAYLOAD" 2>&1)" || http="000"
  if [ "$http" = "200" ]; then
    # L'identifiant Resend est journalisé : HTTP 200 signifie « accepté », pas
    # « délivré ». Quand un mail manque à l'arrivée, c'est le seul élément qui
    # permet de trancher entre un envoi jamais parti et une remise en spam.
    log "rapport envoyé à $ALERT_EMAIL_TO (HTTP 200, id $(python3 -c 'import json,sys;print(json.load(sys.stdin).get("id","?"))' < "$response" 2>/dev/null || echo '?'))"
    rm -f "$response"
    return 0
  fi
  log "ATTENTION: envoi Resend en échec (HTTP $http) : $(head -c 500 "$response" 2>/dev/null)"
  rm -f "$response"
  return 1
}

MAIL_OK=0
send_report && MAIL_OK=1

# ---------------------------------------------------------------------------
# Bilan
# ---------------------------------------------------------------------------
if [ "$STATUS" != "ok" ]; then
  log "=== audit en échec : $FAILURE ==="
  exit 1
fi
if [ "$MAIL_OK" != "1" ]; then
  log "=== rapport produit mais non expédié ==="
  exit 1
fi
log "=== audit terminé — $CRIT critique(s), $WARN alerte(s) ==="
