from collections import Counter
from datetime import UTC, datetime
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
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


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

    .taxii-shell,
    .fabric-shell {
        padding: 1.25rem 1.5rem 2rem;
    }

    .agent-card {
        border: 1px solid #d8dee9;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.85rem;
        background: #ffffff;
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


def get_tactics(stix_object):
    return [
        phase.get("phase_name", "")
        for phase in stix_object.get("kill_chain_phases", [])
        if phase.get("phase_name")
    ]


def summarize_text(text, limit=320):
    if not text:
        return "No description provided."
    clean = " ".join(text.split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3].rstrip() + "..."


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


def run_collection_agent(collection_id, focus_terms, max_items):
    techniques = fetch_taxii_objects(collection_id, "attack-pattern")
    groups = fetch_taxii_objects(collection_id, "intrusion-set")
    software = fetch_taxii_objects(collection_id, "malware,tool")
    relationships = fetch_taxii_objects(collection_id, "relationship")

    terms = [term.strip().casefold() for term in focus_terms.split(",") if term.strip()]

    def matches_focus(item):
        if not terms:
            return True
        haystack = " ".join(
            [
                item.get("name", ""),
                item.get("description", ""),
                get_external_id(item),
                " ".join(get_tactics(item)),
            ]
        ).casefold()
        return any(term in haystack for term in terms)

    selected = [item for item in techniques if matches_focus(item)]
    selected = sorted(
        selected,
        key=lambda item: (len(get_tactics(item)), item.get("modified", "")),
        reverse=True,
    )[:max_items]

    return {
        "agent": "Collection Agent",
        "summary": (
            f"Collected {len(selected)} relevant techniques from "
            f"{len(techniques)} ATT&CK techniques, with {len(groups)} groups and "
            f"{len(software)} software objects available for context."
        ),
        "techniques": selected,
        "groups": groups,
        "software": software,
        "relationships": relationships,
    }


def run_correlation_agent(collection):
    tactic_counts = Counter()
    platform_counts = Counter()
    technique_rows = []

    for technique in collection["techniques"]:
        tactics = get_tactics(technique)
        tactic_counts.update(tactics)
        platform_counts.update(technique.get("x_mitre_platforms", []))
        technique_rows.append(
            {
                "id": get_external_id(technique),
                "name": technique.get("name", "Unnamed technique"),
                "tactics": tactics,
                "platforms": technique.get("x_mitre_platforms", []),
                "description": summarize_text(technique.get("description", ""), 220),
                "url": get_reference_url(technique),
            }
        )

    tactic_sequence = [
        tactic for tactic in TACTIC_ORDER if tactic_counts.get(tactic)
    ] or [tactic for tactic, _ in tactic_counts.most_common()]

    return {
        "agent": "Correlation Agent",
        "summary": (
            f"Correlated {len(technique_rows)} techniques across "
            f"{len(tactic_counts)} tactics and {len(platform_counts)} platforms."
        ),
        "top_tactics": tactic_counts.most_common(8),
        "top_platforms": platform_counts.most_common(8),
        "tactic_sequence": tactic_sequence,
        "techniques": technique_rows,
    }


def run_threat_actor_agent(collection, correlation):
    selected_technique_ids = {
        technique.get("id")
        for technique in collection["techniques"]
        if technique.get("id")
    }
    group_lookup = {
        group.get("id"): group
        for group in collection["groups"]
        if group.get("id")
    }
    relationship_matches = {}

    for relationship in collection.get("relationships", []):
        if relationship.get("relationship_type") != "uses":
            continue
        source_ref = relationship.get("source_ref")
        target_ref = relationship.get("target_ref")
        if source_ref in group_lookup and target_ref in selected_technique_ids:
            relationship_matches.setdefault(source_ref, set()).add(target_ref)

    technique_lookup = {
        technique.get("id"): technique.get("name", "Unnamed technique")
        for technique in collection["techniques"]
        if technique.get("id")
    }
    actor_scores = []

    for group_id, matched_ids in relationship_matches.items():
        group = group_lookup[group_id]
        matched = [technique_lookup[technique_id] for technique_id in matched_ids]
        score = len(matched)
        if score:
            actor_scores.append(
                {
                    "name": group.get("name", "Unnamed group"),
                    "id": get_external_id(group),
                    "score": score,
                    "matched_techniques": sorted(set(matched))[:8],
                    "summary": summarize_text(group.get("description", ""), 260),
                    "url": get_reference_url(group),
                }
            )

    if not actor_scores and selected_technique_ids:
        actor_scores = [
            {
                "name": "Unattributed activity cluster",
                "id": "N/A",
                "score": len(correlation["techniques"]),
                "matched_techniques": [item["name"] for item in correlation["techniques"][:8]],
                "summary": (
                    "No ATT&CK group descriptions directly matched the selected technique set. "
                    "Treat this as a behavior-led cluster until additional evidence identifies an actor."
                ),
                "url": "",
            }
        ]

    actor_scores = sorted(actor_scores, key=lambda item: item["score"], reverse=True)[:5]

    return {
        "agent": "Threat Actor Agent",
        "summary": f"Ranked {len(actor_scores)} likely actor hypotheses from ATT&CK group context.",
        "actors": actor_scores,
    }


def run_writing_agent(collection, correlation, threat_actor):
    top_actor = threat_actor["actors"][0] if threat_actor["actors"] else None
    top_techniques = correlation["techniques"][:8]
    tactic_text = ", ".join(correlation["tactic_sequence"][:8]) or "No tactics identified"
    actor_text = top_actor["name"] if top_actor else "No actor attribution"

    lines = [
        "# Threat Intelligence Assessment",
        "",
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Key Judgement",
        (
            f"The selected ATT&CK evidence indicates activity spanning {tactic_text}. "
            f"The leading attribution hypothesis is {actor_text}, based on overlap between "
            "selected techniques and ATT&CK group context."
        ),
        "",
        "## Observed Techniques",
    ]

    for technique in top_techniques:
        identifier = f"{technique['id']} " if technique["id"] else ""
        lines.append(f"- {identifier}{technique['name']}: {technique['description']}")

    lines.extend(["", "## Actor Hypotheses"])
    for actor in threat_actor["actors"] or []:
        lines.append(
            f"- {actor['name']} ({actor['id']}): score {actor['score']}; "
            f"matched {', '.join(actor['matched_techniques'])}."
        )

    lines.extend(["", "## Recommended Actions"])
    for tactic, _ in correlation["top_tactics"][:5]:
        lines.append(f"- Review detections and response playbooks for {tactic}.")
    lines.append("- Validate hypotheses with telemetry, incident timelines, and internal indicators.")

    return {
        "agent": "Writing Agent",
        "summary": "Drafted an analyst-ready intelligence assessment from the agent outputs.",
        "report": "\n".join(lines),
    }


def run_executive_agent(writing, correlation, threat_actor):
    top_actor = threat_actor["actors"][0]["name"] if threat_actor["actors"] else "unattributed activity"
    top_tactics = ", ".join(tactic for tactic, _ in correlation["top_tactics"][:3]) or "unknown tactics"
    decision_points = [
        "Prioritize validation against internal logs before acting on attribution.",
        "Tune detections for the most common correlated tactics.",
        "Share the assessment with SOC, IR, and leadership stakeholders.",
    ]

    return {
        "agent": "Executive Agent",
        "summary": (
            f"Executive brief: {top_actor} is the leading hypothesis; observed behavior clusters "
            f"around {top_tactics}."
        ),
        "decision_points": decision_points,
        "brief": (
            f"Leadership should treat this as a behavior-led ATT&CK assessment with {top_actor} "
            f"as the current working hypothesis. Immediate value comes from validating telemetry, "
            "closing detection gaps, and keeping attribution confidence separate from operational risk."
        ),
    }


def run_intelligence_fabric(collection_label, focus_terms, max_items):
    collection_id = TAXII_COLLECTIONS[collection_label]
    collection = run_collection_agent(collection_id, focus_terms, max_items)
    correlation = run_correlation_agent(collection)
    threat_actor = run_threat_actor_agent(collection, correlation)
    writing = run_writing_agent(collection, correlation, threat_actor)
    executive = run_executive_agent(writing, correlation, threat_actor)
    return [collection, correlation, threat_actor, writing, executive]


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


def render_agent_card(title, summary):
    st.markdown(
        f"""
        <div class="agent-card">
            <strong>{title}</strong><br>
            <span>{summary}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_intelligence_fabric():
    st.markdown('<div class="fabric-shell">', unsafe_allow_html=True)
    st.title("Multi-Agent Intelligence Fabric")

    st.caption(
        "Collection Agent -> Correlation Agent -> Threat Actor Agent -> "
        "Writing Agent -> Executive Agent"
    )

    control_col, detail_col = st.columns([0.32, 0.68], gap="large")

    with control_col:
        st.subheader("Mission Inputs")
        collection_label = st.selectbox(
            "ATT&CK collection",
            list(TAXII_COLLECTIONS),
            key="fabric_collection",
        )
        focus_terms = st.text_area(
            "Focus terms",
            value="initial access, execution, persistence",
            help="Comma-separated terms matched against technique names, descriptions, IDs, and tactics.",
        )
        max_items = st.slider(
            "Technique budget",
            min_value=5,
            max_value=40,
            value=15,
            step=5,
            help="Limits the number of techniques handed from Collection to Correlation.",
        )
        run_pipeline = st.button("Run Intelligence Fabric", type="primary")

    if run_pipeline:
        try:
            with st.spinner("Running agent workflow against MITRE ATT&CK TAXII data..."):
                st.session_state["fabric_results"] = run_intelligence_fabric(
                    collection_label,
                    focus_terms,
                    max_items,
                )
        except requests.RequestException as exc:
            st.error(f"Unable to run the intelligence fabric: {exc}")
            st.markdown("</div>", unsafe_allow_html=True)
            return

    results = st.session_state.get("fabric_results")

    with detail_col:
        if not results:
            st.info("Set the mission inputs, then run the fabric to generate an intelligence assessment.")
            st.markdown("</div>", unsafe_allow_html=True)
            return

        collection, correlation, threat_actor, writing, executive = results

        st.subheader("Agent Handoff Chain")
        for result in results:
            render_agent_card(result["agent"], result["summary"])

        st.subheader("Correlation View")
        tactic_col, platform_col = st.columns(2)
        with tactic_col:
            st.write("Top tactics")
            st.bar_chart(dict(correlation["top_tactics"]))
        with platform_col:
            st.write("Top platforms")
            st.bar_chart(dict(correlation["top_platforms"]))

        st.subheader("Selected Techniques")
        st.dataframe(
            [
                {
                    "ATT&CK ID": technique["id"],
                    "Technique": technique["name"],
                    "Tactics": ", ".join(technique["tactics"]),
                    "Platforms": ", ".join(technique["platforms"]),
                }
                for technique in correlation["techniques"]
            ],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Threat Actor Hypotheses")
        for actor in threat_actor["actors"]:
            with st.expander(f"{actor['name']} - score {actor['score']}"):
                if actor["url"]:
                    st.markdown(f"[Open ATT&CK reference]({actor['url']})")
                st.write(actor["summary"])
                st.write("Matched techniques:")
                st.write(", ".join(actor["matched_techniques"]))

        st.subheader("Executive Brief")
        st.write(executive["brief"])
        st.write("Decision points:")
        for point in executive["decision_points"]:
            st.write(f"- {point}")

        st.subheader("Analyst Report")
        st.markdown(writing["report"])
        st.download_button(
            "Download Markdown Report",
            data=writing["report"],
            file_name="sentinel-intelligence-assessment.md",
            mime="text/markdown",
        )

    st.markdown("</div>", unsafe_allow_html=True)


portal_tab, taxii_tab, fabric_tab = st.tabs(
    ["SENTINEL Portal", "MITRE ATT&CK TAXII", "Intelligence Fabric"]
)

with portal_tab:
    render_portal()

with taxii_tab:
    render_taxii_explorer()

with fabric_tab:
    render_intelligence_fabric()
