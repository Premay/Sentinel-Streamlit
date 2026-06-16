from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components


APP_DIR = Path(__file__).parent
PORTAL_HTML = APP_DIR / "sentinel-portal.html"


st.set_page_config(
    page_title="SENTINEL Threat Intelligence Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
      .block-container {
        padding: 0;
        max-width: 100%;
      }
      header, footer, [data-testid="stToolbar"], [data-testid="stDecoration"] {
        display: none;
      }
      iframe {
        display: block;
      }
    </style>
    """,
    unsafe_allow_html=True,
)

if not PORTAL_HTML.exists():
    st.error("sentinel-portal.html is missing from this Streamlit app folder.")
    st.stop()

html = PORTAL_HTML.read_text(encoding="utf-8")
components.html(html, height=940, scrolling=True)
