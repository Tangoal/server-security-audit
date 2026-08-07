# CLAUDE.md — server-security-audit

Audit de sécurité hebdomadaire d'un serveur, rédigé par `claude -p` en headless
à partir de faits collectés sur la machine, envoyé par mail via Resend.

## Principe

`audit.sh` fait trois choses, dans cet ordre :

1. **Collecte** une quarantaine de relevés en lecture seule (SSH, pare-feu,
   exposition publique via tunnel et Traefik, ports, comptes et groupes,
   journaux d'authentification et élévations de privilèges, mises à jour et
   noyau, cron, SUID, permissions des secrets, intégrité système). Aucune
   commande ne modifie quoi que ce soit.
2. **Analyse** : ces faits partent dans un seul appel `claude -p … --output-format text`,
   avec une checklist de mise en forme et, s'ils existent sur la machine, les
   documents de contexte listés dans `CONTEXT_FILES`. L'appel est verrouillé —
   modèle épinglé, aucun outil, aucun serveur MCP — pour que deux runs soient
   comparables.
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

Deux relevés lisent malgré tout dans des fichiers de configuration, et le font
par **liste blanche** : la configuration dynamique de Traefik n'affiche que les
clés de structure et une poignée de clés sûres (`rule`, `entrypoints`,
`middlewares`…), parce que ces fichiers portent les empreintes `basicAuth` ; le
tunnel Cloudflare n'affiche que les `hostname`/`service`, jamais son fichier de
credentials `<uuid>.json`. Une liste noire ne conviendrait pas ici : elle
laisse passer ce qu'on n'a pas prévu.

**Le pare-feu ne décrit pas la surface publique.** Sur une machine derrière un
tunnel Cloudflare, `ufw` peut légitimement tout refuser en entrée pendant que
vingt hostnames sont publiés vers Traefik. D'où la section 3 du rapport, qui
croise les hostnames du tunnel avec les routers Traefik et repère ceux qui sont
exposés sans middleware d'authentification. Sans elle, l'audit concluait « ✅
pare-feu cohérent » sur une machine dont toute la surface d'attaque réelle
était ailleurs.

**Le rapport se termine par un marqueur machine-lisible.** La dernière ligne
demandée est `AUDIT_SUMMARY crit=N warn=N unverified=N`. Le script s'en sert
pour deux choses : le décompte de l'objet du mail (champs nommés, pas une regex
sur de la prose), et la **preuve que la réponse est complète** — un rapport
coupé aux deux tiers ne contient aucun 🚨 et partirait avec un objet « RAS ».
Le marqueur est retiré du rapport publié.

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
# 1. Cloner le dépôt (clé de déploiement en lecture seule, cf. plus haut)
git clone git@github.com:Tangoal/server-security-audit.git \
  ~/workspace/infra/server-security-audit && cd $_

# 2. Config locale
cp .env.example .env && chmod 600 .env   # puis remplir SERVER_LABEL, CLAUDE_BIN,
                                         # CLAUDE_RUN_AS, CONTEXT_FILES,
                                         # SENSITIVE_PATHS, Resend

# 3. Vérifier la collecte sans appeler claude ni envoyer de mail
AUDIT_DRY_RUN=/tmp/prompt.txt ./audit.sh && less /tmp/prompt.txt

# 4. Unité + timer, générés depuis le chemin réel du dossier
sudo ./install.sh

# 5. Premier run complet (facultatif, sinon le timer s'en charge lundi)
sudo systemctl start server-security-audit.service
```

La session `claude` doit être authentifiée **pour l'utilisateur `CLAUDE_RUN_AS`**
sur la machine : lancer `claude` une fois en interactif avant le premier run.

L'horaire est **le même sur tous les serveurs** (lundi 04h00 UTC, cf. le timer
généré par `install.sh`) : deux rapports de la même semaine décrivent le parc
au même instant.

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
  (tableau de synthèse + corps de section). L'objet du mail lit le marqueur
  `AUDIT_SUMMARY`, avec repli sur la ligne « Bilan » puis sur le comptage brut
  — dans cet ordre, jamais l'inverse : le comptage brut surestime, ce qui est
  préférable à un « RAS » mensonger.
- **Une troncature silencieuse fait conclure sur des données amputées.** Chaque
  relevé est plafonné à 20 000 octets, et la coupure est désormais écrite dans
  le bloc : un relevé coupé au milieu ressemble en tout point à un relevé
  complet.
- **`sudo` recopie la ligne de commande complète dans le journal**, prompt
  compris. Le relevé des élévations de privilèges coupe donc chaque ligne de
  journal à 200 caractères : sans ça, une invocation précédente du script
  réinjectait des dizaines de milliers de caractères dans le prompt suivant.
- **Chercher « token » ou « credentials » dans un chemin ne cherche pas des
  secrets.** La première version du relevé des secrets versionnés remontait une
  migration `add_token_version.sql` et une doc `ask-before-credentials.md` :
  trois faux positifs sur quatre résultats, et une liste bruitée cesse d'être
  lue. Le motif porte sur le **nom de fichier** seul.
- **Ne pas laisser `AUDIT_MODEL` vide.** Ce serait le modèle de la session
  interactive de `CLAUDE_RUN_AS` : un `/model` un soir changerait la rigueur de
  l'audit du lundi sans que rien ne le signale.

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
