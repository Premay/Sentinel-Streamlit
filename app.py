"""
SENTINEL Threat Intelligence Portal — v2 Only
"""
import streamlit as st
from sentinel_portal_v2 import portal_v2

st.set_page_config(
    page_title="SENTINEL Threat Intelligence Portal",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="collapsed",
)

portal_v2.render()
