# Guide d'enrichissement des modules Red Team — Cahier des charges

Ce guide explique comment mettre à jour les 6 modules Red Team restants pour se conformer aux exigences du rapport technique.

## ✅ Modules déjà enrichis

- ✅ **kerberoasting.py** — complet
- ✅ **password_spray.py** — complet

## ⏳ Modules à enrichir (même pattern)

- asrep_roasting.py
- dcsync.py
- golden_ticket.py
- lateral_mouvement.py
- llmnr_poisoning.py
- pth.py

---

## Pattern à répliquer

Chaque **finding** doit avoir ces 8 champs (au lieu des 4-5 actuels) :

```python
{
    # Champs existants (conservés)
    "risk":      "Critique",       # ✅ EXISTE
    "title":     "...",           # ✅ EXISTE
    "description": "...",         # ✅ EXISTE
    "event_ids": [4768, 4769],    # ✅ EXISTE
    
    # Champs obligatoires à AJOUTER
    "mitigation": "...",          # ✅ Souvent existe mais incomplet
    "mitigation_technique": (     # 🆕 À AJOUTER
        "1. Étape technique 1.\n"
        "2. Étape technique 2."
    ),
    "mitigation_humaine": (       # 🆕 À AJOUTER
        "Formation / sensibilisation / procédure."
    ),
    "impact": "...",              # 🆕 À AJOUTER (ce qu'un attaquant peut faire)
    "logs_siem": [                # 🆕 À AJOUTER (Event IDs + Wazuh rules générés)
        {"event_id": 4768, "description": "..."},
        {"event_id": 4769, "description": "..."},
        {"rule": "Wazuh 12345", "description": "..."},
    ],
}
```

---

## Exemple : AS-REP Roasting

### Avant (actuel)
```python
findings.append({
    "risk":        "Élevé",
    "title":       f"{len(roastable)} roastable account(s) found",
    "description": "Accounts: " + ", ".join(roastable[:5]),
    "mitigation":  "Enable Kerberos pre-authentication on all accounts.",
    "event_ids":   [4768],
})
```

### Après (enrichi) — Pattern à copier
```python
findings.append({
    "risk":        "Élevé",
    "title":       f"{len(roastable)} roastable account(s) found",
    "description": "Accounts: " + ", ".join(roastable[:5]),
    "mitigation":  "Enable Kerberos pre-authentication on all accounts.",
    "mitigation_technique": (
        "1. Activer la pré-authentification Kerberos sur tous les comptes (par défaut).\n"
        "2. Via GPO : Computer Configuration > Windows Settings > Security Settings > Local Policies > "
        "Security Options > Network security: Kerberos preauthentication required.\n"
        "3. Auditer les comptes sans pré-auth via PowerShell.\n"
        "4. Monitorer Event ID 4768 (TGT Request) pour détecter les requêtes sans pré-auth."
    ),
    "mitigation_humaine": (
        "Former les architectes AD à ne jamais désactiver la pré-authentification Kerberos sauf "
        "compatibilité historique strictement justifiée. Intégrer une vérification de ce paramètre "
        "dans la revue de sécurité de tout nouveau déploiement ou de toute modification d'AD."
    ),
    "impact": (
        f"{len(roastable)} compte(s) vulnérable(s) à AS-REP Roasting : un attaquant peut demander un TGT "
        "sans authentification et craquer le hash hors-ligne pour obtenir le mot de passe en clair."
    ),
    "logs_siem": [
        {"event_id": 4768, "description": "Kerberos TGT Request without pre-auth — indicateur de AS-REP Roasting"},
        {"rule": "Wazuh 65432 (exemple)", "description": "Anomalous pre-auth disabled account requests (si activée)"},
    ],
    "event_ids":   [4768],
})
```

---

## Directives par module

### 1️⃣ **asrep_roasting.py** (AS-REP)
- **impact** : Comptes sans pré-auth compromis, mots de passe crackables hors-ligne
- **logs_siem** : Event ID 4768 (TGT Request)
- **mitigation_technique** : Activer pré-auth, auditer via PowerShell, monitorer 4768
- **mitigation_humaine** : Former sur les risques de la désactivation pré-auth, review systématique

### 2️⃣ **dcsync.py** (Sync de domaine, extraction hashes)
- **impact** : Tous les hashes du domaine extraits (krbtgt, DA, etc.), Golden Ticket possible
- **logs_siem** : Event ID 4662 (Directory Service Access), 4624 (Logon) avec droits DRSUAPI
- **mitigation_technique** : Restreindre droits Replication Admin, monitorer 4662 critiquement, centraliser logs
- **mitigation_humaine** : Alerter immédiatement SOC, traiter comme incident critique, former admins

### 3️⃣ **golden_ticket.py** (Golden Ticket)
- **impact** : Accès total au domaine indéfiniment (TGT non expirant forgé avec krbtgt hash)
- **logs_siem** : Event ID 4624 (Logon), 4672 (Special Privileges), absence de 4768 (TGT normal)
- **mitigation_technique** : Rotation krbtgt (2× d'affilée), monitoring des logons SYSTEM CLOCK SKEW
- **mitigation_humaine** : Rotation krbtgt planifiée annuellement, test régulier

### 4️⃣ **lateral_mouvement.py** (Mouvement latéral)
- **impact** : Accès à d'autres serveurs, escalade de privilèges, déploiement de malware
- **logs_siem** : Event ID 4624 (Logon), 4698 (Scheduled Task), 7045 (Service Install)
- **mitigation_technique** : Segmentation réseau, Pass-the-Hash prevention (signing), MFA
- **mitigation_humaine** : Procédure de déploiement sécurisé, formation admins sur les risques

### 5️⃣ **llmnr_poisoning.py** (LLMNR/NBT-NS)
- **impact** : Interception des hashes NTLMv2, escalade vers NTLM Relay / crack hors-ligne
- **logs_siem** : Réseau (pas d'Event ID Windows natif), pattern Suricata/Zeek de poison
- **mitigation_technique** : Désactiver LLMNR/NBT-NS via GPO, utiliser DNSSEC, monitorer réseau
- **mitigation_humaine** : Documenter la désactivation, expliquer risques au réseau

### 6️⃣ **pth.py** (Pass-the-Hash)
- **impact** : Authentification avec hash NTLM sans connaître le mot de passe, accès à ressources
- **logs_siem** : Event ID 4624 (Logon type 3/9), 4648 (Explicit Credentials), SMB Signing disabled
- **mitigation_technique** : Activer SMB Signing (obligatoire), MFA, credential guard, monitorer 4648
- **mitigation_humaine** : Former sur les risques de partage de hash, monitoring des logons anormaux

---

## Checklist pour chaque module

Pour chaque module Red Team, vérifiez que vous avez :

- [ ] `risk` défini correctement (Critique, Élevé, Moyen...)
- [ ] `title` clair et action-oriented
- [ ] `description` détaillée (comptes affectés, hashes trouvés, etc.)
- [ ] `event_ids` listés (Windows Event IDs générés par l'attaque)
- [ ] `mitigation` présent (peut être general ou vague)
- [ ] 🆕 `mitigation_technique` détaillé (GPO, configs, monitoring, outils)
- [ ] 🆕 `mitigation_humaine` avec formation/procédure/sensibilisation
- [ ] 🆕 `impact` décrivant exactement ce qu'un attaquant peut faire (escalade, exfil, etc.)
- [ ] 🆕 `logs_siem` liste les Event IDs + Wazuh rules attendues avec descriptions

---

## Test après enrichissement

Après modification d'un module, testez-le :

```bash
# Relancer le module
python -m modules.red_team.asrep_roasting

# Vérifier que les champs additionnels sont bien dans le résultat
# (les prints du framework doivent afficher tous les champs)

# Générer le rapport PDF technique
python cli.py --red-team kerberoasting,asrep_roasting --report
```

Ouvrez le PDF et vérifiez que le rapport technique affiche :
- ✅ Attaque réalisée
- ✅ Phase / MITRE
- ✅ Outils utilisés
- ✅ **Explication technique** (de `ATTACK_META.description`)
- ✅ **Journaux générés et alertes SIEM** (Event IDs + Wazuh rules de `logs_siem`)
- ✅ **Impact sur AD** (de `impact`)
- ✅ **Recommandations** (fusion de `mitigation` + `mitigation_technique` + `mitigation_humaine`)

---

## Fichiers à modifier

```
modules/red_team/
├── kerberoasting.py              ✅ DONE
├── password_spray.py             ✅ DONE
├── asrep_roasting.py             ⏳ À FAIRE
├── dcsync.py                     ⏳ À FAIRE
├── golden_ticket.py              ⏳ À FAIRE
├── lateral_mouvement.py          ⏳ À FAIRE
├── llmnr_poisoning.py            ⏳ À FAIRE
└── pth.py                        ⏳ À FAIRE
```

---

## Format `logs_siem`

```python
"logs_siem": [
    # Windows Event IDs
    {
        "event_id": 4768,
        "description": "Kerberos TGT Request — indicateur de AS-REP Roasting"
    },
    
    # Wazuh rules (si applicable)
    {
        "rule": "Wazuh 60106",
        "description": "Anomalous TGS request volume detected"
    },
    
    # Pas d'Event ID ? Indiquer-le quand même
    {
        "type": "network",
        "description": "LLMNR/NBT-NS poisoning — détection via Suricata/Zeek uniquement"
    },
]
```

---

## Questions ?

- Si un module ne génère **pas** d'Event ID natif Windows (ex: LLMNR), mettez `[]` ou indiquez "network-only"
- Si vous n'êtes pas sûr de la **Wazuh rule**, mettez juste l'Event ID
- Le **impact** doit dire ce qu'un **attaquant** gagne, pas juste "l'attaque a marché"

Bonne chance ! 🚀
