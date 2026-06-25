# SENTINEL Streamlit App

Run locally:

```bash
python -m pip install -r requirements.txt
streamlit run app.py
```

The app embeds `sentinel-portal.html`, includes a MITRE ATT&CK TAXII explorer backed by `https://attack-taxii.mitre.org/api/v21`, and adds a Multi-Agent Intelligence Fabric:

```text
Collection Agent
        |
        v
Correlation Agent
        |
        v
Threat Actor Agent
        |
        v
Writing Agent
        |
        v
Executive Agent
```

The fabric uses live MITRE ATT&CK TAXII objects, STIX relationships, Streamlit caching, and deterministic agent handoffs to produce an analyst report plus an executive brief.

Keep TAXII requests cached or infrequent because MITRE rate-limits the hosted TAXII service.
