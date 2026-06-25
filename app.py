from pathlib import Path

import requests
import streamlit as st
import streamlit.components.v1 as components


APP_DIR = Path(__file__).parent
PORTAL_HTML = APP_DIR / "sentinel-portal.html"

TAXII_BASE_URL = "https://attack-taxii.mitre.org/api/v21"
TAXII_HEADERS = {"Accept": "application/taxii+json;version=2.1"}
TAXII_COLLECTIONS = {
    "Enterprise ATT&CK": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
    "ICS ATT&CK": "x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09",
    "Mobile ATT&CK": "x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858",
}
STIX_TYPES = {
    "Techniques": "attack-pattern",
    "Groups": "intrusion-set",
    "Software": "malware,tool",
    "Campaigns": "campaign",
    "Mitigations": "course-of-action",
    "Data Sources": "x-mitre-data-source",
    "Data Components": "x-mitre-data-component",
}


st.set_page_config(
    page_title="SENTINEL Threat Intelligence Portal",
    page_icon="S",
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

    .taxii-shell {
        padding: 1.25rem 1.5rem 2rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_external_id(stix_object):
    for reference in stix_object.get("external_references", []):
        external_id = reference.get("external_id")
        if external_id:
            return external_id
    return ""


def get_reference_url(stix_object):
    for reference in stix_object.get("external_references", []):
        url = reference.get("url")
        if url:
            return url
    return ""


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_taxii_objects(collection_id, stix_type):
    response = requests.get(
        f"{TAXII_BASE_URL}/collections/{collection_id}/objects/",
        headers=TAXII_HEADERS,
        params={"match[type]": stix_type},
        timeout=30,
    )
    response.raise_for_status()
    return response.json().get("objects", [])


def render_portal():
    if not PORTAL_HTML.exists():
        st.error("sentinel-portal.html is missing from this Streamlit app folder.")
        st.stop()

    html = PORTAL_HTML.read_text(encoding="utf-8")
    components.html(html, height=1050, scrolling=True)


def render_taxii_explorer():
    st.markdown('<div class="taxii-shell">', unsafe_allow_html=True)
    st.title("MITRE ATT&CK TAXII Feed")

    collection_label = st.selectbox("Collection", list(TAXII_COLLECTIONS))
    object_label = st.selectbox("STIX object type", list(STIX_TYPES))
    search_term = st.text_input("Search", placeholder="Search by name, ATT&CK ID, or description")
    limit = st.slider("Results", min_value=10, max_value=100, value=25, step=5)

    collection_id = TAXII_COLLECTIONS[collection_label]
    stix_type = STIX_TYPES[object_label]

    try:
        objects = fetch_taxii_objects(collection_id, stix_type)
    except requests.RequestException as exc:
        st.error(f"Unable to load TAXII data: {exc}")
        st.markdown("</div>", unsafe_allow_html=True)
        return

    if search_term:
        needle = search_term.casefold()
        objects = [
            item
            for item in objects
            if needle in item.get("name", "").casefold()
            or needle in item.get("description", "").casefold()
            or needle in get_external_id(item).casefold()
        ]

    objects = sorted(objects, key=lambda item: (get_external_id(item), item.get("name", "")))

    st.caption(
        f"Showing {min(limit, len(objects))} of {len(objects)} objects from {collection_label}. "
        "Responses are cached for 1 hour to respect MITRE TAXII rate limits."
    )

    for item in objects[:limit]:
        external_id = get_external_id(item)
        name = item.get("name", "Unnamed object")
        title = f"{external_id} - {name}" if external_id else name

        with st.expander(title):
            reference_url = get_reference_url(item)
            description = item.get("description", "No description provided.")
            platforms = ", ".join(item.get("x_mitre_platforms", []))
            tactics = ", ".join(
                phase.get("phase_name", "")
                for phase in item.get("kill_chain_phases", [])
                if phase.get("phase_name")
            )

            if reference_url:
                st.markdown(f"[Open ATT&CK reference]({reference_url})")
            st.write(description)

            metadata = {
                "STIX ID": item.get("id", ""),
                "Type": item.get("type", ""),
                "Modified": item.get("modified", ""),
                "Platforms": platforms,
                "Tactics": tactics,
            }
            st.json({key: value for key, value in metadata.items() if value})

    st.markdown("</div>", unsafe_allow_html=True)


portal_tab, taxii_tab = st.tabs(["SENTINEL Portal", "MITRE ATT&CK TAXII"])

with portal_tab:
    render_portal()

with taxii_tab:
    render_taxii_explorer()
