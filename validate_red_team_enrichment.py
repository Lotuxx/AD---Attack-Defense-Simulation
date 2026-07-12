#!/usr/bin/env python3
"""
Validation Script — Vérifie que tous les modules Red Team ont les champs requis

Usage:
    python validate_red_team_enrichment.py
    
Outputy:
    - Liste des modules avec status (✅ COMPLET / ⏳ INCOMPLET)
    - Détail des champs manquants par module
    - Recommendations pour compléter
"""

import os
import re
import sys
from pathlib import Path

# Champs obligatoires pour chaque finding Red Team
REQUIRED_FIELDS = {
    "risk": "Niveau de risque (Critique/Élevé/Moyen/Faible/Info)",
    "title": "Titre du finding",
    "description": "Description détaillée",
    "event_ids": "Liste des Event IDs générés",
    "mitigation": "Recommandation générale",
    "mitigation_technique": "🆕 Étapes techniques (GPO, configs, monitoring)",
    "mitigation_humaine": "🆕 Formation, procédure, sensibilisation",
    "impact": "🆕 Ce qu'un attaquant peut faire",
    "logs_siem": "🆕 Event IDs + Wazuh rules avec descriptions",
}

RED_TEAM_DIR = Path("modules/red_team")
MODULES = [
    "kerberoasting.py",
    "password_spray.py",
    "asrep_roasting.py",
    "dcsync.py",
    "golden_ticket.py",
    "lateral_mouvement.py",
    "llmnr_poisoning.py",
    "pth.py",
]

def check_module(filepath):
    """
    Analyse un fichier module et retourne :
    - status: "complete" / "partial" / "error"
    - findings_with_fields: dict d'informations sur les champs trouvés
    - missing_fields: dict des champs manquants
    """
    if not filepath.exists():
        return {
            "status": "error",
            "error": f"Fichier non trouvé : {filepath}",
            "findings_checked": 0,
        }
    
    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception as e:
        return {
            "status": "error",
            "error": f"Erreur lecture : {e}",
        }
    
    # Compter les findings.append
    findings_pattern = r'findings\.append\(\{'
    matches = re.findall(findings_pattern, content)
    total_findings = len(matches)
    
    # Chercher les champs nouveaux (plus fiables que de parser du Python)
    new_fields = {
        "mitigation_technique": r'"mitigation_technique"',
        "mitigation_humaine": r'"mitigation_humaine"',
        "impact": r'"impact"',
        "logs_siem": r'"logs_siem"',
    }
    
    found_fields = {}
    for field, pattern in new_fields.items():
        found = len(re.findall(pattern, content)) > 0
        found_fields[field] = found
    
    # Status
    all_new_fields_present = all(found_fields.values())
    
    if total_findings == 0:
        status = "error"
    elif all_new_fields_present:
        status = "complete"
    else:
        status = "partial"
    
    return {
        "status": status,
        "findings_count": total_findings,
        "new_fields": found_fields,
    }

def main():
    print("=" * 80)
    print("🔍 VALIDATION : Enrichissement des modules Red Team")
    print("=" * 80)
    print()
    
    # Chercher le répertoire modules
    if RED_TEAM_DIR.exists():
        base_dir = Path(".")
    elif Path("AD---Attack-Defense-Simulation-main").exists():
        base_dir = Path("AD---Attack-Defense-Simulation-main")
    else:
        print("❌ Répertoire 'modules/red_team' non trouvé.")
        print("   Lancez ce script depuis la racine du projet.")
        sys.exit(1)
    
    red_team_path = base_dir / RED_TEAM_DIR
    
    print(f"📁 Répertoire analysé : {red_team_path}")
    print()
    
    results = {}
    for module_name in MODULES:
        filepath = red_team_path / module_name
        results[module_name] = check_module(filepath)
    
    # Afficher résumé
    print("╔" + "=" * 78 + "╗")
    print("║" + " RÉSUMÉ PAR MODULE ".center(78) + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    complete_count = 0
    partial_count = 0
    error_count = 0
    
    for module_name, result in results.items():
        status = result.get("status")
        
        if status == "complete":
            print(f"✅ {module_name:30} COMPLET")
            complete_count += 1
        elif status == "partial":
            print(f"⏳ {module_name:30} INCOMPLET")
            partial_count += 1
            # Détail des champs manquants
            new_fields = result.get("new_fields", {})
            missing = [f for f, found in new_fields.items() if not found]
            if missing:
                print(f"   Manquants : {', '.join(missing)}")
        elif status == "error":
            print(f"❌ {module_name:30} ERREUR")
            error_count += 1
            print(f"   {result.get('error', 'Erreur inconnue')}")
        print()
    
    # Statistiques
    print("╔" + "=" * 78 + "╗")
    print("║" + " STATISTIQUES ".center(78) + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    print(f"  Total modules analysés : {len(MODULES)}")
    print(f"  ✅ Complets            : {complete_count} / {len(MODULES)}")
    print(f"  ⏳ Incomplets          : {partial_count} / {len(MODULES)}")
    print(f"  ❌ Erreurs             : {error_count} / {len(MODULES)}")
    print()
    
    if complete_count == len(MODULES):
        print("🎉 TOUS LES MODULES SONT ENRICHIS ! Prêts pour les rapports PDF.")
        return 0
    elif partial_count > 0:
        print("⚠️  Certains modules manquent des champs. Consultez le guide :")
        print("   📖 RED_TEAM_ENRICHMENT_GUIDE.md")
        print()
        print("Champs obligatoires à ajouter à chaque finding :")
        print("  1. mitigation_technique    — Étapes techniques (GPO, config, monitoring)")
        print("  2. mitigation_humaine      — Formation, procédure, sensibilisation")
        print("  3. impact                  — Ce qu'un attaquant peut faire")
        print("  4. logs_siem               — Event IDs + Wazuh rules avec descriptions")
        return 1
    else:
        print("❌ Impossible de valider les modules. Vérifiez le répertoire.")
        return 2

if __name__ == "__main__":
    sys.exit(main())
