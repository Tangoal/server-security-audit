# CLAUDE.md — server-security-audit

Audit de sécurité hebdomadaire d'un serveur, rédigé par `claude -p` en headless
à partir de faits collectés sur la machine, envoyé par mail via Resend.

## Principe

`audit.sh` fait trois choses, dans cet ordre :

1. **Collecte** une trentaine de relevés en lecture seule (SSH, pare-feu, ports,
   comptes et groupes, journaux d'authentification, mises à jour, cron, SUID,
   permissions des secrets). Aucune commande ne modifie quoi que ce soit.
2. **Analyse** : ces faits partent dans un seul appel `claude -p … --output-format text`,
   avec une checklist de mise en forme et, s'ils existent sur la machine, les
   documents de contexte listés dans `CONTEXT_FILES`.
3. **Publie** : rapport dans `reports/<date>.md`, puis mail du rapport intégral
   à `ALERT_EMAIL_TO`.

Le script **ne corrige rien**. Il constate et propose des commandes ; la décision
et l'exécution restent humaines.

## Décisions de conception

**Les faits sont collectés par le script, pas par claude.** Donner l'accès Bash
à un agent pour qu'il aille chercher lui-même l'état du serveur rendait le
résultat non reproductible (chaque run explorait autre chose) et dépendant du
système de permissions en headless. Ici le périmètre est figé dans le script :
d'une semaine à l'autre, deux rapports sont comparables.

**Le mail part à chaque run, même quand tout va bien.** C'est le seul signal de
bonne santé de l'audit : pas de mail le lundi = l'audit ne tourne plus. Un
rapport « RAS » qu'on ne lit pas coûte moins cher qu'une panne silencieuse.

**Les rapports vivent dans le dossier de travail**, donc dans l'archive
quotidienne de `server-backup-gdrive`, sans mécanisme de sauvegarde dédié.

**Le contexte documentaire est optionnel.** `CONTEXT_FILES` évite les faux
positifs sur des choix assumés (ports ouverts volontairement, service exposé,
compte de service). Un chemin absent est ignoré en silence : une machine sans
documentation produit un audit valable, juste plus sévère.

**Aucun secret ne sort de la machine.** Les relevés portent sur des chemins,
des modes et des empreintes — jamais sur le contenu d'un `.env`, d'une clé ou
d'un token. Le prompt et le mail ne contiennent donc rien de confidentiel.
Ne pas ajouter de relevé qui lise le contenu d'un fichier sensible.

## Fichiers

| Fichier | Rôle |
|---|---|
| `audit.sh` | Tout le pipeline. Aucun nom de machine en dur. |
| `install.sh` | Génère et active l'unité + le timer sur la machine courante. |
| `.env` | Config locale de CE serveur (jamais commité, `chmod 600`). |
| `.env.example` | Modèle documenté. |
| `reports/<date>.md` | Rapports produits (jamais commités). |

## Dépôt partagé entre serveurs

Le code vit dans le dépôt **privé** `Tangoal/server-security-audit`, cloné sur
chaque machine. Trois choses n'y sont volontairement pas :

- **`.env`** — il contient la clé Resend.
- **`reports/`** — toutes les machines écrivent `reports/<date>.md`, le même
  chemin : les versionner garantit un conflit chaque lundi. Ils sont déjà
  sauvegardés par l'archive `workspace/` du backup quotidien.
- **Les unités systemd** — leur `ExecStart` dépend du chemin d'installation,
  donc de la machine. `install.sh` les génère dans `/etc/systemd/system` à
  partir de son propre emplacement ; les versionner ferait écraser le chemin
  d'un serveur par celui de l'autre à chaque `git pull`.

Mettre à jour un serveur : `git pull && sudo ./install.sh`.

Les machines qui n'ont pas à pousser utilisent une **clé de déploiement en
lecture seule** (`~/.ssh/id_github_deploy` + entrée `Host github.com` dans
`~/.ssh/config`), pas un token de compte : un serveur compromis ne doit pas
pouvoir réécrire le code d'audit des autres.

## Pourquoi le service tourne en root

Les règles iptables, `/etc/shadow`, les `sudoers` et les journaux
d'authentification ne sont pas lisibles autrement. Deux conséquences :

- **L'appel à claude redescend sur `CLAUDE_RUN_AS`** via `runuser`. La session
  claude est authentifiée dans le home d'un utilisateur normal ; lancer claude
  en root avec `HOME` forcé sèmerait des fichiers root dans son `~/.claude` et
  casserait ses sessions interactives ensuite.
- **`runuser` et pas `sudo`** : `sudo` recopie la ligne de commande complète
  dans le journal système, soit les dizaines de milliers de caractères du prompt
  à chaque run.

Lancé à la main sans privilèges, le script ne s'arrête pas : il marque la
collecte « PARTIEL » et le prompt interdit de conclure ✅ sur une section non
collectée. C'est volontaire — un audit dégradé vaut mieux qu'un audit absent —
mais un rapport « PARTIEL » ne doit pas être lu comme un feu vert.

## Installer sur un nouveau serveur

```bash
# 1. Poser le dossier (le script est identique partout)
scp audit.sh .env.example *.service *.timer serveur:~/workspace/infra/server-security-audit/

# 2. Config locale
cp .env.example .env && chmod 600 .env   # puis remplir CLAUDE_BIN, CLAUDE_RUN_AS,
                                         # CONTEXT_FILES, SENSITIVE_PATHS, Resend

# 3. Vérifier la collecte sans rien appeler ni envoyer
AUDIT_DRY_RUN=/tmp/prompt.txt ./audit.sh && less /tmp/prompt.txt

# 4. Unité + timer (adapter ExecStart au chemin de la machine)
sudo cp server-security-audit.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now server-security-audit.timer
systemctl list-timers server-security-audit.timer
```

L'horaire est **le même sur tous les serveurs** (lundi 07h00 UTC) : deux
rapports de la même semaine décrivent le parc au même instant.

## Pièges rencontrés

- **La session `claude` d'un serveur peu utilisé expire.** Le token OAuth se
  périme et l'appel headless renvoie `401 OAuth access token has expired`. Le
  run échoue proprement (rapport d'échec + mail), mais il faut se reconnecter à
  la main sur la machine (`claude` en interactif) pour le réparer. À surveiller
  sur les serveurs où personne n'ouvre jamais de session.
- **Deux relevés qui cherchent les mêmes fichiers doivent partager leurs
  motifs.** L'inventaire des fichiers sensibles et la liste « lisibles par tous »
  avaient des listes de motifs différentes : un `.env.production` apparaissait
  dans l'un et pas dans l'autre, et le rapport ne pouvait pas trancher. D'où
  `SENSITIVE_FIND_EXPR`, défini une fois et réutilisé.
- **Les couches d'images de conteneurs sont pleines de binaires SUID** (leur
  propre `su`, `passwd`…). Sans `-prune` sur `/var/lib/docker`,
  `/var/lib/containerd` et `/snap`, ils noient les vrais SUID de l'hôte.
- **`AUDIT_DRY_RUN`** dépose le prompt complet et s'arrête avant l'appel : c'est
  l'outil de mise au point, il ne consomme rien et n'envoie rien.
- **L'expéditeur par défaut de Resend coûte deux fois.** Avec
  `onboarding@resend.dev` : `403 validation_error` dès qu'on écrit à quelqu'un
  d'autre que le titulaire du compte, et remise systématique en indésirables
  (domaine partagé, ni SPF ni DKIM au nom de l'envoyeur). Résolu le 2026-08-05
  en vérifiant `tlpcreation.ovh` dans Resend (DKIM `resend._domainkey` + SPF
  `send.tlpcreation.ovh` dans Cloudflare) et en passant
  `ALERT_EMAIL_FROM=alertes@tlpcreation.ovh`.
- **La clé Resend en place est en envoi seul** : elle est rejetée sur `/domains`
  et sur `GET /emails/<id>`. Impossible donc de vérifier le statut de remise
  d'un message depuis la machine — d'où la journalisation de l'id à l'envoi.
- **Compter les 🚨 dans tout le rapport donne le double du vrai chiffre**
  (tableau de synthèse + corps de section). L'objet du mail lit la ligne
  « Bilan » que le rapport produit lui-même.

## Vérifier que ça marche

```bash
./audit.sh                                  # run complet, mail compris
ls -l reports/                              # rapport du jour
systemctl list-timers server-security-audit.timer
journalctl -u server-security-audit.service -n 50
grep -riE "<nom de machine>" audit.sh       # doit rester vide : le script est portable
```

## Hors périmètre

Pas de correction automatique, pas de mise à jour de paquets, pas de
redémarrage de service. Le pipeline de sauvegarde (`server-backup-gdrive`) et
l'audit documentaire des projets (`project-doc-audit`) sont des projets
distincts, sans dépendance avec celui-ci.
