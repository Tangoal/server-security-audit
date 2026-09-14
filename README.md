# server-security-audit

Audit de sécurité hebdomadaire d'un serveur Linux, produit par [Claude
Code](https://claude.com/claude-code) en mode headless (`claude -p`) à partir
de faits collectés en lecture seule sur la machine, puis envoyé par mail via
[Resend](https://resend.com). Aucun nom de machine en dur : tout ce qui est
spécifique à un serveur vit dans un `.env` local, jamais commité.

## Principe

1. **Collecte** — une quarantaine de relevés en lecture seule : pare-feu,
   exposition publique (tunnel + reverse-proxy), ports, comptes et groupes,
   journaux d'authentification et élévations de privilèges, mises à jour et
   noyau, cron, binaires SUID, permissions des secrets, intégrité système.
   Aucune commande ne modifie quoi que ce soit.
2. **Analyse** — les faits collectés partent dans un seul appel `claude -p`
   (modèle épinglé, aucun outil, aucun MCP) avec, s'ils existent, des
   documents de contexte décrivant l'architecture du serveur — évite les faux
   positifs sur des choix assumés (port ouvert volontairement, service
   exposé...).
3. **Publie** — rapport écrit dans `reports/<date>.md`, puis mail du rapport
   intégral.

Le script **ne corrige rien** : il constate et propose des commandes, la
décision et l'exécution restent humaines.

## Pourquoi c'est utile

- Reproductible : le périmètre collecté est figé dans le script (pas
  l'agent), deux rapports d'une semaine à l'autre sont comparables.
- Le mail part à **chaque run, même RAS** : c'est le signal de bonne santé de
  l'audit — pas de mail veut dire que l'audit ne tourne plus.
- Aucun secret ne sort de la machine : les relevés portent sur des chemins et
  des permissions, jamais sur le contenu d'un `.env` ou d'une clé.
- Portable sur un parc de plusieurs serveurs : même code, un `.env` par
  machine.

## Installation

```bash
git clone https://github.com/Tangoal/server-security-audit.git
cd server-security-audit
cp .env.example .env && chmod 600 .env   # puis remplir (voir commentaires du fichier)

# Vérifier la collecte sans appeler claude ni envoyer de mail
AUDIT_DRY_RUN=/tmp/prompt.txt ./audit.sh && less /tmp/prompt.txt

sudo ./install.sh                        # service + timer hebdomadaire
```

Prérequis : [Claude Code](https://claude.com/claude-code) installé et
authentifié pour l'utilisateur configuré dans `CLAUDE_RUN_AS`.

## Documentation

Décisions de conception, pièges rencontrés, procédure d'installation
détaillée : [`AGENTS.md`](./AGENTS.md).

## Hors périmètre

Pas de correction automatique, pas de mise à jour de paquets, pas de
redémarrage de service.

## Licence

MIT.
