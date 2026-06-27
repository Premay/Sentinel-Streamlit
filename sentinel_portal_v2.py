"""
SENTINEL Portal v2 — Modular Dashboard
Embeds the sentinel-portal-v2.2.html file with Streamlit components.
"""
from pathlib import Path
import streamlit as st
import streamlit.components.v1 as components

APP_DIR = Path(__file__).parent
PORTAL_V2_HTML = APP_DIR / "sentinel-portal-v2.2.html"

class PortalV2:
    def render(self):
        st.markdown("<br>", unsafe_allow_html=True)

        if not PORTAL_V2_HTML.exists():
            st.error("sentinel-portal-v2.2.html is missing from the app folder.")
            st.info("Please ensure sentinel-portal-v2.2.html is in the same directory as app.py")
            st.stop()

        html = PORTAL_V2_HTML.read_text(encoding="utf-8")
        components.html(html, height=1050, scrolling=True)

portal_v2 = PortalV2()
