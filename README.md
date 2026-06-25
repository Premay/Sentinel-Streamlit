# SENTINEL Streamlit App

Run locally:

```bash
python -m pip install -r requirements.txt
streamlit run app.py
```

The app embeds `sentinel-portal.html` and includes a MITRE ATT&CK TAXII explorer backed by `https://attack-taxii.mitre.org/api/v21`.

Keep TAXII requests cached or infrequent because MITRE rate-limits the hosted TAXII service.
