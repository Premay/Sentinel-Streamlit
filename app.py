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
      header.stAppHeader,
      header[data-testid="stHeader"] {
        display: none !important;
        visibility: hidden !important;
        height: 0 !important;
        min-height: 0 !important;
      }
      div[data-testid="stToolbar"],
      div[data-testid="stDecoration"],
      div[data-testid="stStatusWidget"],
      #MainMenu {
        display: none !important;
        visibility: hidden !important;
      }
      footer { visibility: hidden !important; }

      .block-container {
        padding: 0 !important;
        margin: 0 !important;
        max-width: 100% !important;
      }
      div[data-testid="stAppViewContainer"],
      div[data-testid="stMain"],
      div[data-testid="stAppViewBlockContainer"] {
        padding-top: 0 !important;
        margin-top: 0 !important;
      }
      div[data-testid="element-container"] {
        margin: 0 !important;
        padding: 0 !important;
      }
      body, .stApp {
        margin: 0 !important;
        padding: 0 !important;
      }
      iframe {
        display: block;
        width: 100% !important;
        border: none;
      }
    </style>
    """,
    unsafe_allow_html=True,
)

if not PORTAL_HTML.exists():
    st.error("sentinel-portal.html is missing from this Streamlit app folder.")
    st.stop()

html = PORTAL_HTML.read_text(encoding="utf-8")
components.html(html, height=1050, scrolling=True)
