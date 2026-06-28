"""
SENTINEL Portal v2 — Modular Dashboard
Embeds the sentinel-portal-v2.2.html file with Streamlit components.
Fixes: removes white gap and sliding animation issues.
"""
from pathlib import Path
import streamlit as st
import streamlit.components.v1 as components

APP_DIR = Path(__file__).parent
PORTAL_V2_HTML = APP_DIR / "sentinel-portal-v2.2.html"

class PortalV2:
    def render(self):
        # Remove default Streamlit padding and margins
        st.markdown("""
            <style>
                /* Remove Streamlit default padding */
                .stApp {
                    margin: 0 !important;
                    padding: 0 !important;
                }
                .main .block-container {
                    padding: 0 !important;
                    margin: 0 !important;
                    max-width: 100% !important;
                }
                iframe {
                    border: none !important;
                    margin: 0 !important;
                    padding: 0 !important;
                    width: 100% !important;
                }
                /* Hide Streamlit header/footer if present */
                header {
                    visibility: hidden;
                }
            </style>
        """, unsafe_allow_html=True)

        if not PORTAL_V2_HTML.exists():
            st.error("sentinel-portal-v2.2.html is missing from the app folder.")
            st.info("Please ensure sentinel-portal-v2.2.html is in the same directory as app.py")
            st.stop()

        html = PORTAL_V2_HTML.read_text(encoding="utf-8")

        # Inject CSS to fix the sliding animation and white gap inside the HTML itself
        fix_css = """
        <style>
            /* Remove login transition that causes sliding */
            #login-screen {
                transition: none !important;
            }
            /* Ensure body/html fill the iframe with no gaps */
            html, body {
                margin: 0 !important;
                padding: 0 !important;
                width: 100% !important;
                height: 100% !important;
                overflow: hidden !important;
                background: var(--bg-base, #0a0e17) !important;
            }
            /* Remove any default margins from the app container */
            #app {
                margin: 0 !important;
                padding: 0 !important;
            }
        </style>
        """

        # Insert the fix CSS right before </head>
        if "</head>" in html:
            html = html.replace("</head>", fix_css + "</head>")
        else:
            # If no head tag, prepend
            html = fix_css + html

        # Use components.html with full width and no scrolling gaps
        components.html(html, height=1050, scrolling=True)

portal_v2 = PortalV2()
