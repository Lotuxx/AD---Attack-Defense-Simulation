"""
Streamlit Dashboard — AD Attack & Defense Visualization
========================================================
Run: streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from core.database import DatabaseManager

# ── Configuration ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="AD Attack & Defense — Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
    <style>
    .main { padding-top: 1rem; }
    [data-testid="stMetric"] {
        background-color: #1e1e1e;
        border: 1px solid #444;
        border-radius: 8px;
        padding: 1rem;
    }
    [data-testid="stMetricLabel"] {
        color: #ffffff !important;
        font-size: 14px !important;
    }
    [data-testid="stMetricValue"] {
        color: #00ff88 !important;
        font-size: 2rem !important;
    }
    </style>
""", unsafe_allow_html=True)

# ── DB ────────────────────────────────────────────────────────────────────────

@st.cache_resource
def get_db():
    return DatabaseManager()

db = get_db()

# ── Sidebar ───────────────────────────────────────────────────────────────────

st.sidebar.markdown("# 🛡️ AD Security Lab")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    ["📊 Overview", "🔴 Red Team", "🔵 Blue Team", "🟣 Purple Team", "📈 Analytics", "⚙️ Settings"],
)

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Refresh:** {datetime.now().strftime('%H:%M:%S')}")
if st.sidebar.button("🔄 Refresh"):
    st.rerun()

# ── Page 1: Overview ──────────────────────────────────────────────────────────

if page == "📊 Overview":
    st.title("🛡️ AD Attack & Defense — Live Dashboard")
    st.markdown("**NISSEKONG Georges Owen | DIOP Salla — 2025-2026**")
    st.markdown("---")

    stats = db.get_global_stats()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("⚔️ Attaques lancées", stats.get("total_executions", 0))
    with col2:
        st.metric("✅ Taux de succès", f"{stats.get('success_rate', 0):.0f}%")
    with col3:
        st.metric("🚨 Findings critiques", stats.get("critical_findings", 0))
    with col4:
        st.metric("🎯 Taux détection", f"{stats.get('avg_detection_rate', 0):.0f}%")

    st.markdown("---")

    # Timeline Red Team
    st.subheader("📅 Historique des attaques")
    executions = db.get_execution_history()
    if executions:
        df = pd.DataFrame(executions)
        df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M')
        st.dataframe(
            df[['timestamp', 'attack_name', 'target_ip', 'target_domain', 'status', 'duration_s']].rename(columns={
                'timestamp': 'Date',
                'attack_name': 'Attaque',
                'target_ip': 'Cible',
                'target_domain': 'Domaine',
                'status': 'Statut',
                'duration_s': 'Durée (s)',
            }),
            use_container_width=True,
            height=300,
        )
    else:
        st.info("Aucune attaque enregistrée. Lancez une attaque Red Team.")

    st.markdown("---")

    # Findings distribution
    st.subheader("🎯 Distribution des findings")
    findings_summary = db.get_findings_summary()
    if findings_summary:
        col1, col2 = st.columns(2)
        with col1:
            st.dataframe(pd.DataFrame(list(findings_summary.items()), columns=['Risque', 'Count']), use_container_width=True)
        with col2:
            for level, count in findings_summary.items():
                color = "🔴" if level == "Critique" else "🟠" if level == "Élevé" else "🟡" if level == "Moyen" else "🟢"
                st.metric(f"{color} {level}", count)
    else:
        st.info("Aucun finding. Lancez un audit Blue Team.")

# ── Page 2: Red Team ──────────────────────────────────────────────────────────

elif page == "🔴 Red Team":
    st.title("🔴 Red Team — Historique des attaques")
    st.markdown("---")

    attacks = db.get_execution_history()

    if attacks:
        df = pd.DataFrame(attacks)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp', ascending=False)

        # Filtres
        col1, col2 = st.columns(2)
        with col1:
            attack_types = ["Toutes"] + list(df['attack_name'].unique())
            selected = st.selectbox("Filtrer par attaque:", attack_types)
        with col2:
            status_types = ["Tous"] + list(df['status'].unique())
            selected_status = st.selectbox("Filtrer par statut:", status_types)

        if selected != "Toutes":
            df = df[df['attack_name'] == selected]
        if selected_status != "Tous":
            df = df[df['status'] == selected_status]

        # Tableau
        display_df = df[['timestamp', 'attack_name', 'target_ip', 'target_domain', 'status', 'duration_s']].copy()
        display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M')
        st.dataframe(
            display_df.rename(columns={
                'timestamp': 'Date',
                'attack_name': 'Attaque',
                'target_ip': 'Cible IP',
                'target_domain': 'Domaine',
                'status': 'Statut',
                'duration_s': 'Durée (s)',
            }),
            use_container_width=True,
            height=400,
        )

        st.markdown("---")

        # Stats
        col1, col2, col3 = st.columns(3)
        with col1:
            success = (df['status'] == 'success').sum()
            st.metric("✅ Succès", success)
        with col2:
            partial = (df['status'] == 'partial').sum()
            st.metric("⚠️ Partiels", partial)
        with col3:
            failed = (df['status'].isin(['failed', 'error'])).sum()
            st.metric("❌ Échoués", failed)

        # Graphique succès par attaque
        st.subheader("📊 Succès par type d'attaque")
        attack_stats = df.groupby('attack_name')['status'].apply(
            lambda x: round((x == 'success').sum() / len(x) * 100, 1)
        ).reset_index()
        attack_stats.columns = ['Attaque', 'Taux succès (%)']
        # graphique désactivé)

    else:
        st.info("Aucune attaque enregistrée.")

# ── Page 3: Blue Team ─────────────────────────────────────────────────────────

elif page == "🔵 Blue Team":
    st.title("🔵 Blue Team — Audit de sécurité")
    st.markdown("---")

    findings = db.get_findings_history()

    if findings:
        df = pd.DataFrame(findings)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp', ascending=False)

        # Filtres
        col1, col2 = st.columns(2)
        with col1:
            audit_types = ["Tous"] + list(df['audit_type'].unique())
            selected_audit = st.selectbox("Filtrer par module:", audit_types)
        with col2:
            risk_types = ["Tous"] + list(df['risk_level'].unique())
            selected_risk = st.selectbox("Filtrer par risque:", risk_types)

        if selected_audit != "Tous":
            df = df[df['audit_type'] == selected_audit]
        if selected_risk != "Tous":
            df = df[df['risk_level'] == selected_risk]

        # Tableau
        display_df = df[['timestamp', 'audit_type', 'risk_level', 'title', 'target_domain']].copy()
        display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M')
        st.dataframe(
            display_df.rename(columns={
                'timestamp': 'Date',
                'audit_type': 'Module',
                'risk_level': 'Risque',
                'title': 'Finding',
                'target_domain': 'Domaine',
            }),
            use_container_width=True,
            height=400,
        )

        st.markdown("---")

        # Stats
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🔴 Critiques", len(df[df['risk_level'] == 'Critique']))
        with col2:
            st.metric("🟠 Élevés", len(df[df['risk_level'] == 'Élevé']))
        with col3:
            st.metric("🟡 Moyens", len(df[df['risk_level'] == 'Moyen']))
        with col4:
            st.metric("📋 Total", len(df))

        # Graphique par module
        st.subheader("📊 Findings par module d'audit")
        module_counts = df.groupby('audit_type').size().reset_index(name='count')
        # graphique désactivé)

    else:
        st.info("Aucun finding. Lancez un audit Blue Team.")

# ── Page 4: Purple Team ───────────────────────────────────────────────────────

elif page == "🟣 Purple Team":
    st.title("🟣 Purple Team — Validation de détection")
    st.markdown("---")

    rates = db.get_detection_rate()
    stats = db.get_global_stats()

    # Taux global
    avg_rate = stats.get('avg_detection_rate', 0)
    color = "🟢" if avg_rate >= 80 else "🟡" if avg_rate >= 50 else "🔴"
    st.metric(f"{color} Taux de détection global", f"{avg_rate:.0f}%")

    st.markdown("---")

    if rates:
        # Tableau détection par attaque
        st.subheader("📊 Détection par attaque")
        rows = [{"Attaque": k, "Taux (%)": v["rate"], "Runs": v["runs"]} for k, v in rates.items()]
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True)

        st.markdown("---")

        # Graphique
        st.subheader("📈 Taux de détection par attaque")
        chart_df = df.set_index('Attaque')['Taux (%)']
        # graphique désactivé

        # Résumé
        detected = sum(1 for v in rates.values() if v['rate'] >= 50)
        missed = len(rates) - detected
        col1, col2 = st.columns(2)
        with col1:
            st.metric("✅ Attaques détectées", detected)
        with col2:
            st.metric("❌ Attaques non détectées", missed)
    else:
        st.info("Aucune donnée de détection. Lancez le Purple Team.")

# ── Page 5: Analytics ─────────────────────────────────────────────────────────

elif page == "📈 Analytics":
    st.title("📈 Analytics — Vue globale")
    st.markdown("---")

    stats = db.get_global_stats()

    # Stats globales
    st.subheader("📊 Statistiques globales")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("⚔️ Total attaques", stats.get("total_executions", 0))
        st.metric("✅ Succès", stats.get("successful_attacks", 0))
        st.metric("📈 Taux succès", f"{stats.get('success_rate', 0):.0f}%")
    with col2:
        st.metric("🔍 Total findings", stats.get("total_findings", 0))
        st.metric("🚨 Critiques/Élevés", stats.get("critical_findings", 0))
    with col3:
        st.metric("🎯 Taux détection moyen", f"{stats.get('avg_detection_rate', 0):.0f}%")

    st.markdown("---")

    # Succès par cible
    st.subheader("🎯 Succès par cible")
    attacks = db.get_execution_history()
    if attacks:
        df = pd.DataFrame(attacks)
        if 'target_ip' in df.columns and df['target_ip'].notna().any():
            target_stats = df[df['target_ip'].notna()].groupby('target_ip').agg(
                Total=('status', 'count'),
                Succès=('status', lambda x: (x == 'success').sum()),
            )
            target_stats['Taux (%)'] = (target_stats['Succès'] / target_stats['Total'] * 100).round(1)
            st.dataframe(target_stats, use_container_width=True)
        else:
            st.info("Pas assez de données par cible.")
    else:
        st.info("Aucune attaque enregistrée.")

    st.markdown("---")

    # Catalogue des attaques
    st.subheader("📚 Catalogue des attaques (CDC)")
    catalog = db.get_attack_catalog()
    if catalog:
        cat_df = pd.DataFrame(catalog)
        st.dataframe(
            cat_df[['name', 'type', 'mitre_id', 'risk_level', 'tools']].rename(columns={
                'name': 'Attaque',
                'type': 'Type',
                'mitre_id': 'MITRE',
                'risk_level': 'Risque',
                'tools': 'Outils',
            }),
            use_container_width=True,
        )

# ── Page 6: Settings ──────────────────────────────────────────────────────────

elif page == "⚙️ Settings":
    st.title("⚙️ Paramètres")
    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📥 Export des données")

        attacks = db.get_execution_history()
        if attacks and st.button("📊 Exporter attaques CSV"):
            df = pd.DataFrame(attacks)
            csv = df.to_csv(index=False)
            st.download_button(
                label="⬇️ Télécharger",
                data=csv,
                file_name=f"attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )

        findings = db.get_findings_history()
        if findings and st.button("📋 Exporter findings CSV"):
            df = pd.DataFrame(findings)
            csv = df.to_csv(index=False)
            st.download_button(
                label="⬇️ Télécharger",
                data=csv,
                file_name=f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )

        if st.button("🔄 Rafraîchir le dashboard"):
            st.rerun()

    with col2:
        st.subheader("ℹ️ À propos")
        st.info(
            "**AD Attack & Defense Simulation**\n\n"
            "NISSEKONG Georges Owen | DIOP Salla\n"
            "2025-2026\n\n"
            "Dashboard temps réel basé sur SQLite.\n"
            "Alimenté automatiquement par le framework CLI."
        )

        stats = db.get_global_stats()
        st.json({
            "total_executions": stats.get("total_executions", 0),
            "total_findings": stats.get("total_findings", 0),
            "avg_detection_rate": f"{stats.get('avg_detection_rate', 0):.0f}%",
        })

# ── Footer ────────────────────────────────────────────────────────────────────

st.markdown("---")
st.markdown(
    "**AD Attack & Defense Simulation Framework** | "
    "NISSEKONG Georges Owen | DIOP Salla | 2025-2026"
)
