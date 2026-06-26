# 🛡️ Sentinel Portal v2 — Installation Guide

## What's New in v2

Sentinel Portal v2 is a complete modular rewrite of the original threat intelligence dashboard with:

- **Modular Architecture**: Clean separation of components, data layer, AI agents, and pages
- **Dark Theme**: Professional cybersecurity aesthetic
- **Enhanced Navigation**: Sidebar-based navigation with 6 dedicated pages
- **AI Agents**: Collection, Correlation, Enrichment, and Briefing agents
- **MITRE ATT&CK Integration**: Full TAXII sync with technique mapping
- **IOC Management**: Advanced filtering, search, and enrichment
- **Dark Web Intelligence**: Ransomware tracking, data leak monitoring, access brokers
- **Report Generator**: AI-powered executive and analyst reports
- **Settings Panel**: Full configuration for feeds, AI, users, and system

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the App

**Option A: Integrated mode** (v1 + v2 tabs)
```bash
streamlit run app.py
```

**Option B: Standalone v2**
```bash
streamlit run app_v2.py
```

### 3. Access the Portal

Open your browser to: `http://localhost:8501`

## Folder Structure

```
sentinel-portal-v2/
├── __init__.py              # Package init
├── portal_v2.py             # Main entry point
├── components/              # Reusable UI components
│   ├── threat_cards.py      # KPI cards, alarms, charts
│   ├── ioc_table.py         # IOC table with filters
│   ├── actor_profile.py     # Actor profile cards
│   ├── dark_web_monitor.py  # Dark web feeds
│   ├── cve_tracker.py       # CVE dashboard
│   └── executive_brief.py   # Report preview
├── data/                    # Data layer
│   ├── feed_connectors.py   # Feed connections
│   ├── ioc_database.py      # IOC storage
│   └── mitre_sync.py        # MITRE ATT&CK sync
├── agents/                  # AI agents
│   ├── collection_agent.py  # Data collection
│   ├── correlation_agent.py # Data correlation
│   ├── enrichment_agent.py  # IOC enrichment
│   └── briefing_agent.py    # Report generation
├── pages/                   # Page modules
│   ├── dashboard.py         # Main dashboard
│   ├── ioc_manager.py     # IOC management
│   ├── actor_intelligence.py # Actor intel
│   ├── dark_web_intel.py  # Dark web page
│   ├── report_generator.py # Reports
│   └── settings.py         # Configuration
├── utils/                   # Utilities
│   ├── config.py            # Configuration
│   ├── cache.py             # Caching
│   └── styling.py           # Theme
└── assets/                  # Static assets
    └── sentinel_theme.css   # Custom CSS
```

## Pages Overview

| Page | Description |
|------|-------------|
| 📊 Dashboard | KPIs, threat trends, CVE tracker, feed status |
| 🔍 IOC Manager | Search, filter, add, and export IOCs |
| 🎭 Actor Intelligence | Threat actor profiles with MITRE mapping |
| 🌑 Dark Web Intel | Ransomware, leaks, access brokers, fintech |
| 📄 Report Generator | AI-powered executive & analyst reports |
| ⚙️ Settings | Data sources, AI config, users, system |

## Integration with v1

The updated `app.py` includes a new tab "🆕 Portal v2" that embeds the entire v2 dashboard alongside the existing v1 portal, TAXII explorer, and Intelligence Fabric.

## Customization

- Edit `utils/config.py` to change feed sources, IOC types, and intervals
- Modify `assets/sentinel_theme.css` for custom styling
- Extend `agents/` with new intelligence agents
- Add new pages in `pages/` and register them in `portal_v2.py`

## License

Same as original Sentinel-Streamlit repository.
