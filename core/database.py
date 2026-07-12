"""
Core — Database Management Layer
=================================

This module provides the persistence layer of the AD Attack & Defense
Simulation Framework.

The database stores all information generated during simulations:

    Red Team:
        - Attack catalog.
        - Attack execution history.
        - Execution artifacts.

    Blue Team:
        - Security audit findings.
        - Risk assessment results.

    Purple Team:
        - Wazuh detection results.
        - Detection performance metrics.

Data flow:

        Attack / Audit Modules
                 |
                 v
          DatabaseManager
                 |
                 v
             SQLite DB
                 |
        +--------+---------+
        |                  |
     Dashboard          Reports


Database location:
    reports/attacks.db

SQLite was selected because:
    - The framework is designed for isolated security labs.
    - No external database server is required.
    - Easy portability between machines.

The DatabaseManager class provides:
    - Database initialization.
    - Data insertion.
    - Statistics calculation.
    - Historical analysis.
"""

import sqlite3
import os
import json
from datetime import datetime
from typing import Optional

# ============================================================================
# Database location
# ============================================================================
# The SQLite database is stored inside the reports directory because:
#
#   - Reports and collected simulation data belong together.
#   - The database remains local to the framework instance.
#   - The project can be moved easily between lab environments.
#
# For production environments, this could be replaced by:
#   - PostgreSQL,
#   - MySQL,
#   - Cloud database,
#   - SIEM backend storage.
# ============================================================================
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "attacks.db")


class DatabaseManager:
    """
    Central database interface for the framework.

    This class hides all SQLite operations from the rest of the project.

    Other components should not directly execute SQL queries.
    They should use DatabaseManager methods instead.

    Responsibilities:
        - Create database schema.
        - Store execution results.
        - Store findings.
        - Store detection information.
        - Provide statistics for dashboard/reporting.
    """

    def __init__(self, db_path: str = DB_PATH):
        """
    Initialize the database manager.

    Steps:
        1. Store database location.
        2. Create reports directory if missing.
        3. Initialize database schema.
        4. Insert default attack catalog.

    Args:
        db_path:
            Path of the SQLite database file.
    """
        
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _connect(self):
        """
    Create a SQLite database connection.

    Row factory is configured so query results behave like dictionaries:

        row["attack_name"]

    instead of:

        row[0]

    This improves readability throughout the framework.
    """
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """
Create the framework database schema.

The schema contains four main entities:

    attacks:
        Static catalog of supported attack techniques.

    executions:
        History of Red Team simulations.

    findings:
        Blue Team audit results.

    detections:
        Purple Team correlation between attacks and SIEM alerts.


The database is automatically created on first execution.
"""
        # ============================================================================
# Database schema creation
# ============================================================================
# CREATE TABLE IF NOT EXISTS avoids destroying previous laboratory results.
#
# Existing execution history and findings are preserved between framework
# launches.
# ============================================================================
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS attacks (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT NOT NULL UNIQUE,
                    type            TEXT NOT NULL,
                    mitre_id        TEXT,
                    risk_level      TEXT NOT NULL,
                    preconditions   TEXT,
                    exploit         TEXT,
                    impact          TEXT,
                    mitigation      TEXT,
                    tools           TEXT,
                    event_ids       TEXT,
                    created_at      TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS executions (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    attack_name     TEXT NOT NULL,
                    target_ip       TEXT,
                    target_domain   TEXT,
                    status          TEXT NOT NULL,
                    duration_s      REAL,
                    findings_count  INTEGER DEFAULT 0,
                    artifacts       TEXT,
                    timestamp       TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (attack_name) REFERENCES attacks(name)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    module          TEXT NOT NULL,
                    audit_type      TEXT NOT NULL,
                    risk_level      TEXT NOT NULL,
                    title           TEXT NOT NULL,
                    description     TEXT,
                    mitigation      TEXT,
                    target_ip       TEXT,
                    target_domain   TEXT,
                    timestamp       TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS detections (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id    INTEGER,
                    attack_name     TEXT NOT NULL,
                    alert_count     INTEGER DEFAULT 0,
                    rule_ids        TEXT,
                    detected        INTEGER DEFAULT 0,
                    detection_rate  REAL DEFAULT 0.0,
                    timestamp       TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (execution_id) REFERENCES executions(id)
                );
            """)
            self._seed_attacks()


    def _seed_attacks(self):
        """
Populate the attack catalog with supported techniques.

This table represents the offensive techniques covered by the project CDC.

Each attack entry contains:

    - MITRE ATT&CK technique ID.
    - Required conditions.
    - Exploitation method.
    - Expected impact.
    - Recommended mitigations.
    - Detection event IDs.

INSERT OR IGNORE ensures:
    - First launch creates the catalog.
    - Future launches do not duplicate entries.
"""

        # ============================================================================
# Supported attack catalogue
# ============================================================================
# The catalog acts as the knowledge base of the simulation framework.
#
# It allows:
#   - Dashboard visualization.
#   - Reporting.
#   - Attack documentation.
#   - MITRE ATT&CK mapping.
# ============================================================================
        attacks = [
            {
                "name":          "Kerberoasting",
                "type":          "Credential Access",
                "mitre_id":      "T1558.003",
                "risk_level":    "Élevé",
                "preconditions": "Compte utilisateur valide dans le domaine. Présence de comptes avec SPN enregistré.",
                "exploit":       "impacket-GetUserSPNs extrait les tickets TGS chiffrés avec le hash NTLM du compte de service. Craquage hors-ligne avec Hashcat mode 13100.",
                "impact":        "Compromission du compte de service. Escalade de privilèges possible si le compte a des droits élevés.",
                "mitigation":    "1. Mots de passe longs (>25 car.) pour tous les comptes de service.\n2. Utiliser des gMSA (Group Managed Service Accounts).\n3. Monitorer Event ID 4769 en masse.\n4. Limiter les SPN aux comptes strictement nécessaires.",
                "tools":         "impacket-GetUserSPNs, Hashcat",
                "event_ids":     "4769",
            },
            {
                "name":          "Password Spraying",
                "type":          "Credential Access",
                "mitre_id":      "T1110.003",
                "risk_level":    "Élevé",
                "preconditions": "Liste d'utilisateurs du domaine. Politique de verrouillage faible ou absente.",
                "exploit":       "netexec teste un mot de passe commun contre tous les comptes du domaine en respectant le seuil de verrouillage pour éviter le blocage.",
                "impact":        "Obtention de credentials valides. Accès initial au domaine.",
                "mitigation":    "1. Activer le verrouillage de compte (≤10 tentatives).\n2. Implémenter MFA.\n3. Désactiver les comptes inactifs.\n4. Monitorer Event ID 4625 en masse.",
                "tools":         "netexec, CrackMapExec",
                "event_ids":     "4625, 4740",
            },
            {
                "name":          "Pass-the-Hash",
                "type":          "Lateral Movement",
                "mitre_id":      "T1550.002",
                "risk_level":    "Critique",
                "preconditions": "Hash NTLM d'un compte administrateur. Droits de réplication AD (DCSync) ou accès à la mémoire LSASS.",
                "exploit":       "impacket-secretsdump extrait les hashes NTLM via DCSync. Le hash est utilisé directement pour s'authentifier sans connaître le mot de passe en clair.",
                "impact":        "Accès complet au domaine. Compromission de tous les comptes AD.",
                "mitigation":    "1. Activer Credential Guard.\n2. Déployer LAPS.\n3. Désactiver NTLMv1.\n4. Activer Protected Users Security Group.\n5. Restreindre les droits de réplication AD.",
                "tools":         "impacket-secretsdump, impacket-wmiexec",
                "event_ids":     "4624, 4648, 4662",
            },
            {
                "name":          "Lateral Movement",
                "type":          "Lateral Movement",
                "mitre_id":      "T1021.002",
                "risk_level":    "Élevé",
                "preconditions": "Credentials valides (login/password ou hash NTLM). Accès réseau à la cible.",
                "exploit":       "impacket-wmiexec exécute des commandes à distance via WMI en s'authentifiant avec les credentials obtenus. Accès SYSTEM obtenu.",
                "impact":        "Exécution de code à distance. Accès SYSTEM sur la machine cible. Propagation dans le réseau.",
                "mitigation":    "1. Segmenter le réseau (VLAN).\n2. Restreindre l'accès ADMIN$.\n3. Désactiver WMI si non nécessaire.\n4. Monitorer Event ID 4688 + 7045.",
                "tools":         "impacket-psexec, impacket-wmiexec, impacket-smbexec",
                "event_ids":     "4624, 4688, 7045",
            },
            {
                "name":          "LLMNR Poisoning",
                "type":          "Credential Access",
                "mitre_id":      "T1557.001",
                "risk_level":    "Élevé",
                "preconditions": "Attaquant sur le même segment réseau que les victimes. LLMNR/NBT-NS activé sur les machines Windows.",
                "exploit":       "Responder répond aux requêtes LLMNR/NBT-NS broadcast et capture les hashes NTLMv2 lors de la tentative d'authentification. Craquage hors-ligne avec Hashcat mode 5600.",
                "impact":        "Capture de hashes NTLMv2. Si SMB Signing désactivé : relay attack possible sans craquage.",
                "mitigation":    "1. Désactiver LLMNR via GPO.\n2. Désactiver NBT-NS (propriétés TCP/IP).\n3. Activer SMB Signing.\n4. Déployer un honeypot LLMNR pour la détection.",
                "tools":         "Responder, Inveigh",
                "event_ids":     "Aucun Event ID Windows natif — détection réseau uniquement",
            },
        ]

        with self._connect() as conn:
            for attack in attacks:
                conn.execute("""
                    INSERT OR IGNORE INTO attacks
                    (name, type, mitre_id, risk_level, preconditions, exploit, impact, mitigation, tools, event_ids)
                    VALUES (:name, :type, :mitre_id, :risk_level, :preconditions, :exploit, :impact, :mitigation, :tools, :event_ids)
                """, attack)

    
    # ── Red Team ──────────────────────────────────────────────────────────────

    # ============================================================================
# Red Team data management
# ============================================================================
# Stores offensive simulation results:
#
#   - Executed attack.
#   - Target machine.
#   - Domain.
#   - Execution status.
#   - Duration.
#   - Collected artifacts.
#
# This information is later used by:
#   - Reports.
#   - Dashboard.
#   - Purple Team correlation.
# ============================================================================

    def log_execution(self, attack_name: str, target_ip: str, target_domain: str,
                      status: str, duration_s: float, findings: list, artifacts: dict = None) -> int:
        """
Store a Red Team attack execution.

An execution record allows the framework to track:
    - What attack was performed.
    - Against which target.
    - Whether it succeeded.
    - How long it lasted.
    - What artifacts were generated.

Args:
    findings:
        List of findings generated during execution.

    artifacts:
        Additional execution information stored as JSON.
"""

        with self._connect() as conn:
            cursor = conn.execute("""
                INSERT INTO executions (attack_name, target_ip, target_domain, status, duration_s, findings_count, artifacts)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                attack_name, target_ip, target_domain, status,
                duration_s, len(findings),
                json.dumps(artifacts or {})
            ))
            return cursor.lastrowid

    # ── Blue Team ─────────────────────────────────────────────────────────────

    # ============================================================================
# Blue Team findings storage
# ============================================================================
# Stores security weaknesses discovered during audits.
#
# Findings are later consumed by:
#   - Dashboard risk views.
#   - PDF reports.
#   - Audit comparison functions.
# ============================================================================

    def log_findings(self, module: str, audit_type: str, findings: list,
                     target_ip: str = "", target_domain: str = ""):
        """
Store Blue Team audit findings.

Each finding contains:
    - Audit module.
    - Risk level.
    - Description.
    - Recommended mitigation.
    - Target information.

One audit can generate multiple database entries.
"""

        with self._connect() as conn:
            for f in findings:
                conn.execute("""
                    INSERT INTO findings (module, audit_type, risk_level, title, description, mitigation, target_ip, target_domain)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    module, audit_type,
                    f.get("risk", "Info"),
                    f.get("title", ""),
                    f.get("description", ""),
                    f.get("mitigation", ""),
                    target_ip, target_domain
                ))

    # ── Purple Team ───────────────────────────────────────────────────────────

    # ============================================================================
# Purple Team detection storage
# ============================================================================
# Records the relationship between:
#
#       Simulated attack
#              +
#       SIEM detection result
#
# Used to measure defensive visibility.
# ============================================================================

    def log_detection(self, execution_id: Optional[int], attack_name: str,
                      alert_count: int, rule_ids: list, detected: bool, detection_rate: float):
        """
Store SIEM detection results.

Information stored:
    - Related execution.
    - Attack technique.
    - Number of alerts generated.
    - Detection rules triggered.
    - Detection percentage.

This allows measurement of SOC effectiveness.
"""

        with self._connect() as conn:
            conn.execute("""
                INSERT INTO detections (execution_id, attack_name, alert_count, rule_ids, detected, detection_rate)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                execution_id, attack_name, alert_count,
                json.dumps(rule_ids), int(detected), detection_rate
            ))

    # ── Statistiques ──────────────────────────────────────────────────────────

    # ============================================================================
# Reporting and analytics functions
# ============================================================================
# These methods provide aggregated information for:
#
#   - CLI statistics command.
#   - Streamlit dashboard.
#   - Security reports.
#
# They transform raw database records into analyst-friendly information.
# ============================================================================

    def get_attack_catalog(self) -> list:
        """Retourne le catalogue complet des attaques (CDC page 10)."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM attacks ORDER BY type, name").fetchall()
            return [dict(row) for row in rows]

    def get_execution_history(self, attack_name: str = None) -> list:
        """Retourne l'historique des exécutions."""
        with self._connect() as conn:
            if attack_name:
                rows = conn.execute(
                    "SELECT * FROM executions WHERE attack_name = ? ORDER BY timestamp DESC",
                    (attack_name,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM executions ORDER BY timestamp DESC"
                ).fetchall()
            return [dict(row) for row in rows]

    def get_findings_summary(self, target_domain: str = None) -> dict:
        """Retourne un résumé des findings Blue Team par niveau de risque."""
        with self._connect() as conn:
            query = "SELECT risk_level, COUNT(*) as count FROM findings"
            params = ()
            if target_domain:
                query += " WHERE target_domain = ?"
                params = (target_domain,)
            query += " GROUP BY risk_level ORDER BY CASE risk_level WHEN 'Critique' THEN 1 WHEN 'Élevé' THEN 2 WHEN 'Moyen' THEN 3 WHEN 'Faible' THEN 4 ELSE 5 END"
            rows = conn.execute(query, params).fetchall()
            return {row["risk_level"]: row["count"] for row in rows}

    def get_findings_history(self) -> list:
        """Retourne l historique complet des findings Blue Team."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT module, audit_type, risk_level, title, description, target_ip, target_domain, timestamp FROM findings ORDER BY timestamp DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def get_detection_rate(self, attack_name: str = None) -> dict:
        """Calcule le taux de détection global ou par attaque."""
        with self._connect() as conn:
            if attack_name:
                rows = conn.execute(
                    "SELECT detected, detection_rate FROM detections WHERE attack_name = ? ORDER BY timestamp DESC LIMIT 10",
                    (attack_name,)
                ).fetchall()
                if not rows:
                    return {"attack": attack_name, "rate": 0, "runs": 0}
                avg_rate = sum(r["detection_rate"] for r in rows) / len(rows)
                return {"attack": attack_name, "rate": round(avg_rate, 1), "runs": len(rows)}
            else:
                rows = conn.execute(
                    "SELECT attack_name, AVG(detection_rate) as avg_rate, COUNT(*) as runs FROM detections GROUP BY attack_name"
                ).fetchall()
                return {row["attack_name"]: {"rate": round(row["avg_rate"], 1), "runs": row["runs"]} for row in rows}

    def get_global_stats(self) -> dict:
        """
Calculate global framework statistics.

Returned indicators:

    total_executions:
        Number of Red Team simulations.

    successful_attacks:
        Successful offensive operations.

    success_rate:
        Percentage of successful attacks.

    total_findings:
        Number of Blue Team findings.

    critical_findings:
        Number of high-risk weaknesses.

    avg_detection_rate:
        Average Purple Team detection capability.
"""

        with self._connect() as conn:
            total_executions = conn.execute("SELECT COUNT(*) FROM executions").fetchone()[0]
            successful       = conn.execute("SELECT COUNT(*) FROM executions WHERE status = 'success'").fetchone()[0]
            total_findings   = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            critical         = conn.execute("SELECT COUNT(*) FROM findings WHERE risk_level IN ('Critique', 'Élevé')").fetchone()[0]
            avg_detection    = conn.execute("SELECT AVG(detection_rate) FROM detections").fetchone()[0] or 0

            return {
                "total_executions":   total_executions,
                "successful_attacks": successful,
                "success_rate":       round(successful / total_executions * 100, 1) if total_executions else 0,
                "total_findings":     total_findings,
                "critical_findings":  critical,
                "avg_detection_rate": round(avg_detection, 1),
            }

    def compare_audits(self, domain: str, before_date: str, after_date: str) -> dict:
        """
Compare security posture before and after hardening.

This function helps measure remediation effectiveness.

Example:

Before:
    Critical findings = 5

After:
    Critical findings = 1

Delta:
    Improvement of 4 findings

Used for:
    - Security improvement tracking.
    - Before/after audit reports.
"""

        with self._connect() as conn:
            def get_findings_at(date):
                return conn.execute("""
                    SELECT risk_level, COUNT(*) as count FROM findings
                    WHERE target_domain = ? AND timestamp <= ?
                    GROUP BY risk_level
                """, (domain, date)).fetchall()

            before = {r["risk_level"]: r["count"] for r in get_findings_at(before_date)}
            after  = {r["risk_level"]: r["count"] for r in get_findings_at(after_date)}

            return {
                "domain":  domain,
                "before":  before,
                "after":   after,
                "delta": {
                    level: after.get(level, 0) - before.get(level, 0)
                    for level in set(list(before.keys()) + list(after.keys()))
                }
            }
