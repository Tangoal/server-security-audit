# Goal — server-security-audit (audit sécu hebdo via Claude headless)

## Condition
`infra/server-security-audit/audit.sh` tourne sur `ghost` et sur le VPS `vps-tlpcreation` (même code, `.env` distinct, aucune référence en dur à un nom de machine — `grep -riE "ghost|vps-tlpcreation" audit.sh` ne retourne rien), via un timer systemd hebdomadaire actif à la **même heure sur les deux machines** (lundi 07h00 UTC, après les runs de `server-backup-gdrive` à 3h et `gdrive-nas-mirror` à 6h sur ghost), invoque `claude -p "<prompt checklist>" --output-format text` en incluant dans le prompt le contenu de `CLAUDE.md`/`workspace/docs/INFRA.md` **si présents sur la machine** (vérifiés via `[ -f ... ]` avant inclusion, pas d'échec si absents), couvre au minimum SSH (config + `authorized_keys`), pare-feu (`ufw` + règles `DOCKER-USER`/iptables), ports en écoute, groupes utilisateurs à risque (`docker`, `lxd`), logs d'authentification/brute-force, mises à jour de sécurité en attente, tâches cron, fichiers SUID/SGID inhabituels, et permissions des fichiers sensibles (`.env`, clés SSH, tokens) ; écrit le rapport dans `infra/server-security-audit/reports/<date>.md` (donc automatiquement inclus dans le backup quotidien de `workspace/` par `server-backup-gdrive`) ; envoie **systématiquement** le contenu du rapport par mail via Resend à `ALERT_EMAIL_TO`, que l'audit soit positif ou négatif (sert aussi de heartbeat : l'absence de mail hebdo signale un problème sur l'audit lui-même).

## Contexte
Ancien script `maintenance/audit-secu/vps-audit-secu.sh` retrouvé (rien n'a été supprimé le 2026-08-05, tout a été déplacé dans `/home/tangoal/maintenance/`) — pattern déjà validé par la pratique (`claude -p` headless, rapport `.md`, log séparé), repris comme base. Le rapport d'exemple du 2026-03-19 (topologie VPS avant migration Traefik, avec nginx-proxy-manager) sert de référence pour le niveau de détail attendu de la checklist. Le vieux `vps-maintenance.sh` associé (apt upgrade auto + docker prune, alerte SMTP avec mot de passe d'application Gmail en clair dans `.env`) est explicitement abandonné — hors périmètre, `unattended-upgrades` gère déjà les mises à jour côté VPS, et le pattern SMTP/mot de passe d'application est remplacé par Resend partout dans ce projet de reconstruction (voir `infra/server-backup-gdrive/GOAL.md`).

## Vérification
- `bash infra/server-security-audit/audit.sh` exécuté manuellement sur `ghost` termine avec succès, un fichier `reports/<date>.md` est créé avec un contenu structuré couvrant tous les points de la checklist, et un mail est effectivement reçu à `ALERT_EMAIL_TO` via Resend.
- Même exécution sur le VPS via `ssh vps-tlpcreation`, avec son propre `.env` — le rapport ne mentionne pas de faux positif sur des choix déjà documentés dans un `CLAUDE.md`/`INFRA.md` local s'il en existe un.
- `grep -riE "ghost|vps-tlpcreation" infra/server-security-audit/audit.sh` ne retourne aucune occurrence hors commentaires génériques.
- `systemctl list-timers` montre le timer actif au même horaire hebdomadaire sur les deux machines (lundi 07h00 UTC).
- Le rapport du jour apparaît dans l'archive `workspace.tar.gz` du backup quotidien suivant (preuve qu'il est bien inclus sans mécanisme dédié).

## Périmètre
- Dans le périmètre : `audit.sh`, `.env.example`, `CLAUDE.md` du dossier, unit + timer systemd, prompt de checklist, intégration Resend (envoi systématique), déploiement sur `ghost` ET le VPS.
- Hors périmètre : `vps-maintenance.sh` (apt upgrade auto + docker prune, abandonné), correction automatique des problèmes trouvés (l'audit constate et propose des commandes, il n'exécute rien lui-même), `server-backup-gdrive`, `gdrive-nas-mirror`, `project-doc-audit`, tout futur 3ᵉ serveur.

## Condition d'arrêt
- Si le prompt de checklist produit un rapport incohérent ou tronqué sur un run de test, s'arrêter et ajuster le prompt plutôt que de le déployer en l'état.
- Si l'inclusion conditionnelle de `CLAUDE.md`/`INFRA.md` fait dépasser une taille de prompt problématique (notamment `INFRA.md` qui est un fichier long), s'arrêter et demander s'il faut en extraire un résumé plutôt que le fichier entier.
- Si `RESEND_API_KEY` n'est pas encore configuré au moment du premier run réel, s'arrêter plutôt que de laisser échouer l'envoi en silence.

## Statut
**Atteint — 2026-08-05**

| Vérification | `ghost` | VPS |
|---|---|---|
| Run du service en root réussi (`Result=success`, code 0) | ✅ | ✅ |
| Rapport `reports/2026-08-05.md`, 9 domaines, 0 « non vérifié » | ✅ 23 Ko | ✅ 10 Ko |
| Mail Resend envoyé | ✅ HTTP 200 | ✅ HTTP 200 |
| Timer actif lundi 07h00 UTC | ✅ | ✅ |

- `grep -riE "<nom de machine>" audit.sh` : aucune occurrence. Script identique
  au md5 près sur les deux machines (`b85f4b94…`), seuls les `.env` diffèrent.
- Inclusion du rapport dans l'archive `workspace.tar.gz` vérifiée en rejouant les
  exclusions du backup quotidien (pas d'attente du run de 3h nécessaire).
- Le run dégradé (sans root) a aussi été éprouvé sur le VPS : il marque
  `🔍 Non vérifié` sur le pare-feu et les mises à jour et ne conclut jamais ✅
  sur une section non collectée.

Ajout non prévu au périmètre initial, décidé en cours de route : le code vit
dans le dépôt privé `Tangoal/server-security-audit`, et `install.sh` génère
l'unité systemd depuis son propre chemin — sans quoi un `git pull` écrasait
l'`ExecStart` d'un serveur par celui de l'autre. Le VPS tire via une clé de
déploiement en lecture seule, pas un token de compte.

Premières conclusions des audits (rien n'a été corrigé — l'audit constate) :
`ghost` a 7 fichiers de secrets en `o+r` et `markup/{docs,src}` en `0707` alors
que le conteneur `markup`, public, monte `/home/tangoal` en écriture ; le VPS a
deux `.env` lisibles par tous, 25 158 échecs SSH en 7 jours, et `dockhand` avec
le socket Docker en écriture.

Décision d'exploitation : la clé Resend fournie est en **envoi seul** et le
compte n'a **aucun domaine vérifié**, donc `onboarding@resend.dev` ne peut
écrire qu'au titulaire du compte. `ALERT_EMAIL_TO` vaut donc
`tlpcreation.dev@gmail.com` (et non `tanguylprs@gmail.com`) sur les deux
machines, ici comme dans `server-backup-gdrive`. Pour revenir à l'autre adresse :
vérifier `tlpcreation.ovh` dans Resend, puis passer `ALERT_EMAIL_FROM` sur une
adresse de ce domaine.
