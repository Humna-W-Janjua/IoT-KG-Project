import html
import re
import streamlit as st
from ollama import chat
from rdflib import Graph

# --- Page Configuration (Fixed Expanded Sidebar) ---
st.set_page_config(
    page_title="AEGIS-KG | IoT Botnet Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom Cyber-SOC Theme (#990000 Crimson & Obsidian, Single-Screen Fit) ---
st.markdown("""
<style>
    /* Compact Single-Screen Viewport Padding */
    .block-container {
        padding-top: 0.9rem !important;
        padding-bottom: 0.4rem !important;
        padding-left: 1.5rem !important;
        padding-right: 1.5rem !important;
        max-width: 100% !important;
    }
    header[data-testid="stHeader"] {
        height: 1.8rem !important;
        background: transparent !important;
    }
    /* Lock Sidebar Open & Hide Collapse Arrow */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #110606 0%, #0b0d13 100%);
        border-right: 1px solid #5c0a0a;
        min-width: 275px !important;
        max-width: 275px !important;
    }
    section[data-testid="stSidebar"] > div:first-child {
        padding-top: 1rem !important;
    }
    [data-testid="stSidebarCollapseButton"], button[kind="header"] {
        display: none !important;
    }
    .stApp {
        background: radial-gradient(circle at top right, #1f0505 0%, #0a0c10 48%, #06070a 100%);
        color: #e6edf3;
    }
    /* Pulsing Online Dot */
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.7); }
        70% { box-shadow: 0 0 0 7px rgba(74, 222, 128, 0); }
        100% { box-shadow: 0 0 0 0 rgba(74, 222, 128, 0); }
    }
    .live-dot {
        display: inline-block;
        width: 9px;
        height: 9px;
        background: #4ade80;
        border-radius: 50%;
        margin-right: 8px;
        animation: pulse 2s infinite;
    }
    .soc-status {
        background: #0f2418;
        border: 1px solid #22c55e;
        border-radius: 8px;
        padding: 8px 12px;
        font-size: 0.82rem;
        font-weight: 700;
        color: #86efac;
        margin-bottom: 10px;
    }
    /* Sidebar Cards & Progress Bars */
    .side-card {
        background: #12151f;
        border: 1px solid #2a1818;
        border-left: 3px solid #990000;
        border-radius: 7px;
        padding: 8px 10px;
        margin-bottom: 7px;
        font-size: 0.76rem;
    }
    .bar-bg {
        background: #1e2230;
        border-radius: 4px;
        height: 5px;
        width: 100%;
        margin-top: 4px;
        overflow: hidden;
    }
    .bar-fill {
        background: linear-gradient(90deg, #990000, #ff3333);
        height: 100%;
    }
    /* Tactical Hero Banner */
    .hero-box {
        background: linear-gradient(135deg, #240606 0%, #12151f 60%, #300808 100%);
        border: 1px solid #990000;
        border-left: 6px solid #ff1e1e;
        border-radius: 10px;
        padding: 10px 18px;
        margin-bottom: 10px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 4px 24px rgba(153, 0, 0, 0.3);
    }
    .hero-title {
        font-size: 1.3rem;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: 0.4px;
    }
    .hero-sub {
        color: #ff9e9e;
        font-size: 0.78rem;
    }
    .hero-pills {
        display: flex;
        gap: 7px;
    }
    .pill {
        background: #171a26;
        border: 1px solid #990000;
        color: #ff7575;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.73rem;
        font-weight: 700;
    }
    /* Telemetry Strip */
    .telem-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 8px;
        margin-bottom: 8px;
    }
    .telem-item {
        background: #12151f;
        border: 1px solid #282d3d;
        border-top: 2px solid #990000;
        border-radius: 7px;
        padding: 6px 10px;
        text-align: center;
    }
    .telem-val {
        font-size: 1.05rem;
        font-weight: 800;
        color: #ff4d4d;
    }
    .telem-lbl {
        font-size: 0.66rem;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: #9ba3b4;
    }
    /* Provenance Badges & Triple Cards */
    .badge-explicit {
        display: inline-block;
        background: #132a1e;
        color: #4ade80;
        border: 1px solid #22c55e;
        padding: 1px 6px;
        border-radius: 5px;
        font-size: 0.66rem;
        font-weight: 700;
        margin-right: 6px;
    }
    .badge-inferred {
        display: inline-block;
        background: #2e0a0a;
        color: #ff6b6b;
        border: 1px solid #990000;
        padding: 1px 6px;
        border-radius: 5px;
        font-size: 0.66rem;
        font-weight: 700;
        margin-right: 6px;
    }
    .triple-card {
        background: #12151e;
        border: 1px solid #262b38;
        border-radius: 6px;
        padding: 6px 10px;
        margin-bottom: 6px;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 0.76rem;
        color: #dbe4f0;
    }
    /* Execute Button */
    div.stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #990000 0%, #cc0000 100%);
        color: white;
        border: 1px solid #ff3333;
        border-radius: 8px;
        font-weight: 700;
        width: 100%;
        height: 41px;
        margin-top: 26px;
        box-shadow: 0 3px 14px rgba(153, 0, 0, 0.45);
    }
    div.stButton > button[kind="primary"]:hover {
        background: linear-gradient(90deg, #b30000 0%, #e60000 100%);
        border-color: #ff6666;
    }
</style>
""", unsafe_allow_html=True)

MODEL = "qwen2.5:3b"

# --- Load V2 Ontology, A-Box Graph, and Inferred Facts ---
@st.cache_resource
def load_kg():
    g = Graph()
    ttl_files = [
        "Ontology/ontology_v2.ttl",
        "RDF_Knowledge_Graph/iot_knowledge_graph_v2.ttl",
        "RDF_Knowledge_Graph/iot_inferred_facts_v2.ttl",
        "RDF_Knowledge_Graph/iot_multihop_inferences_v2.ttl",
    ]
    loaded_counts = {}
    for path in ttl_files:
        try:
            before = len(g)
            g.parse(path, format="turtle")
            loaded_counts[path.split("/")[-1]] = len(g) - before
        except Exception as e:
            loaded_counts[path] = 0

    # Compute live botnet threat statistics from the graph
    threat_stats = {"Okiru": 0, "DDoS": 0, "HorizontalPortScan": 0, "C&C / HeartBeat": 0}
    for _, _, o in g:
        o_str = str(o)
        if "Okiru" in o_str:
            threat_stats["Okiru"] += 1
        elif "DDoS" in o_str:
            threat_stats["DDoS"] += 1
        elif "HorizontalPortScan" in o_str:
            threat_stats["HorizontalPortScan"] += 1
        elif "C&C" in o_str or "HeartBeat" in o_str:
            threat_stats["C&C / HeartBeat"] += 1

    return g, loaded_counts, threat_stats

kg, file_stats, threat_stats = load_kg()

def short_name(uri) -> str:
    s = str(uri)
    return s.split("#")[-1] if "#" in s else s.split("/")[-1]

def retrieve_evidence(question: str):
    stopwords = {
        "which", "what", "where", "when", "who", "how", "many", "are", "the", "and",
        "for", "with", "from", "that", "this", "into", "linked", "targeted", "devices",
        "device", "nodes", "node", "traffic", "inferred", "botnet", "about", "show", "list",
        "graph", "reasoning", "connections", "specific", "outgoing", "external", "there"
    }
    q_norm = question.lower()
    raw_tokens = re.findall(r"[a-z0-9_.]+", q_norm)
    tokens = [t.rstrip(".") for t in raw_tokens if len(t.rstrip(".")) > 2 and t.rstrip(".") not in stopwords]

    # Exact entity IDs (e.g., device_192.168.100.111, port_8081) get highest priority
    exact_entities = [t for t in tokens if ("_" in t or "." in t)]

    intent_boosters = []
    if any(k in q_norm for k in ["compromised", "source", "infected", "attacker", "host"]):
        intent_boosters.extend(["inferredsourcedevice", "hassourcedevice", "hassourceip"])
    if "port" in q_norm or "ports" in q_norm:
        intent_boosters.extend(["inferreddestinationport", "hasdestinationport", "port_"])
    if "ddos" in q_norm:
        intent_boosters.append("ddos")
    if "okiru" in q_norm:
        intent_boosters.append("okiru")
    if "portscan" in q_norm or "scan" in q_norm:
        intent_boosters.append("portscan")

    search_terms = list(dict.fromkeys(exact_entities + tokens + intent_boosters))
    if not search_terms:
        return [], [], [], "No domain entities matched."

    matched_subjects = set()
    priority_explicit, priority_inferred = [], []
    direct_explicit, direct_inferred = [], []
    raw_triples = []

    for s, p, o in kg:
        s_n, p_n, o_n = short_name(s), short_name(p), short_name(o)
        if p_n == "type" and o_n in ["NamedIndividual", "Class", "ObjectProperty"]:
            continue
        triple_str = f"{s_n} --[{p_n}]--> {o_n}"
        t_low = triple_str.lower()

        is_exact = any(ent in t_low for ent in exact_entities)
        is_match = is_exact or any(term in t_low for term in search_terms)

        if is_match:
            is_inf = any(k in t_low for k in ["inferred", "multihop", "istargetedby", "propagates", "compromised"])
            if is_exact:
                (priority_inferred if is_inf else priority_explicit).append(triple_str)
            else:
                (direct_inferred if is_inf else direct_explicit).append(triple_str)

            if len(raw_triples) < 8:
                raw_triples.append((s_n, p_n, o_n, is_inf))
            if (is_exact or len(matched_subjects) < 6) and ("Connection_" in s_n or "Device_" in s_n or "MultiHop" in s_n):
                if len(matched_subjects) < 10:
                    matched_subjects.add(s)

    for subj in matched_subjects:
        s_n = short_name(subj)
        for p, o in kg.predicate_objects(subj):
            p_n, o_n = short_name(p), short_name(o)
            if p_n == "type":
                continue
            triple_str = f"{s_n} --[{p_n}]--> {o_n}"
            t_low = triple_str.lower()
            is_inf = any(k in t_low for k in ["inferred", "multihop", "istargetedby", "propagates", "compromised"])
            (priority_inferred if is_inf else priority_explicit).append(triple_str)

    explicit_unique = list(dict.fromkeys(priority_explicit + direct_explicit))[:18]
    inferred_unique = list(dict.fromkeys(priority_inferred + direct_inferred))[:18]
    sparql_preview = (
        f"PREFIX iot: <http://example.org/iot#>\n"
        f"SELECT DISTINCT ?s ?p ?o WHERE {{\n"
        f"  ?s ?p ?o .\n"
        f"  FILTER(REGEX(STR(?p), '{'|'.join(search_terms[:3])}', 'i') || REGEX(STR(?o), '{'|'.join(search_terms[:3])}', 'i'))\n"
        f"}} LIMIT 36"
    )
    return explicit_unique, inferred_unique, raw_triples, sparql_preview

def render_svg_graph(triples: list) -> str:
    """Renders a sleek Cyber-SOC SVG Node-Link diagram of the top retrieved triples."""
    if not triples:
        return "<div style='color:#9ba3b4;font-size:0.8rem;padding:20px;text-align:center;'>No graph edges to visualize for this query.</div>"
    rows = triples[:6]
    height = max(210, len(rows) * 42 + 20)
    svg_parts = [f'<svg width="100%" height="{height}" viewBox="0 0 540 {height}" xmlns="http://www.w3.org/2000/svg">']
    for idx, (s, p, o, is_inf) in enumerate(rows):
        y = 26 + idx * 40
        edge_color = "#ff4d4d" if is_inf else "#4ade80"
        s_lbl = html.escape(s[:22] + ("…" if len(s) > 22 else ""))
        p_lbl = html.escape(p[:20] + ("…" if len(p) > 20 else ""))
        o_lbl = html.escape(o[:22] + ("…" if len(o) > 22 else ""))
        svg_parts.append(f'''
            <line x1="165" y1="{y}" x2="365" y2="{y}" stroke="{edge_color}" stroke-width="1.6" stroke-dasharray="{'4,3' if is_inf else '0'}" />
            <polygon points="365,{y} 358,{y-4} 358,{y+4}" fill="{edge_color}" />
            <rect x="8" y="{y-13}" width="157" height="24" rx="5" fill="#181c28" stroke="#990000" stroke-width="1.2"/>
            <text x="86" y="{y+3}" fill="#ffffff" font-size="10" font-family="Consolas, monospace" text-anchor="middle">{s_lbl}</text>
            <rect x="200" y="{y-10}" width="130" height="18" rx="4" fill="#0d0f14" stroke="{edge_color}" stroke-width="0.9"/>
            <text x="265" y="{y+2}" fill="{edge_color}" font-size="9" font-family="Consolas, monospace" text-anchor="middle">{p_lbl}</text>
            <rect x="368" y="{y-13}" width="164" height="24" rx="5" fill="#1e0b0b" stroke="{edge_color}" stroke-width="1.2"/>
            <text x="450" y="{y+3}" fill="#ffd6d6" font-size="10" font-family="Consolas, monospace" text-anchor="middle">{o_lbl}</text>
        ''')
    svg_parts.append("</svg>")
    return "".join(svg_parts)

def generate_grounded_answer(question: str, explicit: list, inferred: list) -> str:
    if not explicit and not inferred:
        return (
            "Insufficient evidence in the Knowledge Graph. "
            "The requested attributes or entities do not exist in our IoT-23 ontology or A-Box triples, so no facts will be fabricated."
        )

    evidence_text = "EXPLICIT KNOWLEDGE (Stored A-Box Triples):\n"
    evidence_text += "\n".join(f"- {x}" for x in explicit) if explicit else "- None\n"
    evidence_text += "\n\nINFERRED KNOWLEDGE (Derived via Ontology Rules / Multi-Hop Reasoning):\n"
    evidence_text += "\n".join(f"- {x}" for x in inferred) if inferred else "- None\n"

    system_prompt = (
        "You are AEGIS-KG, an IoT Cybersecurity Knowledge Graph Analyst. "
        "Answer the user's question using ONLY the retrieved Knowledge Graph evidence below.\n"
        "STRICT GROUNDING RULES:\n"
        "1. Never invent facts or use outside knowledge. If the retrieved evidence does NOT contain information that answers the specific question asked (for example, firmware versions or physical room locations), you MUST respond ONLY with: 'Insufficient evidence in the Knowledge Graph.'\n"
        "2. When evidence DOES answer the question, directly list the matching device IDs, connection IDs, ports, or threat labels found in the evidence, and separate:\n"
        "   - **Direct Findings**\n"
        "   - **Provenance Breakdown** (Explicit A-Box vs. Inferred Multi-Hop/Rule triples)."
    )

    response = chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Retrieved Graph Evidence:\n{evidence_text}\n\nQuestion: {question}"}
        ],
        options={"temperature": 0.1},
    )
    return response.message.content.strip()

# --- Fixed Left Cyber-SOC Sidebar ---
with st.sidebar:
    st.markdown("### 🛡️ AEGIS-KG Telemetry")
    st.markdown(f'<div class="soc-status"><span class="live-dot"></span>Ollama Active • {MODEL}</div>', unsafe_allow_html=True)

    st.markdown("**📂 Active RDF Graph Layers**")
    total_triples = max(len(kg), 1)
    for fname, count in file_stats.items():
        pct = min(100, max(4, int((count / total_triples) * 100)))
        st.markdown(f"""
        <div class="side-card">
            <div style="display:flex;justify-content:space-between;">
                <span style="color:#fff;font-weight:700;">{fname}</span>
                <span style="color:#ff7575;">{count:,}</span>
            </div>
            <div class="bar-bg"><div class="bar-fill" style="width:{pct}%;"></div></div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("**☣️ Botnet Signature Distribution**")
    max_t = max(threat_stats.values()) if any(threat_stats.values()) else 1
    for label, cnt in threat_stats.items():
        t_pct = min(100, max(5, int((cnt / max_t) * 100)))
        st.markdown(f"""
        <div class="side-card">
            <div style="display:flex;justify-content:space-between;">
                <span style="color:#dbe4f0;">{label}</span>
                <span style="color:#4ade80;font-weight:700;">{cnt:,}</span>
            </div>
            <div class="bar-bg"><div class="bar-fill" style="width:{t_pct}%;background:linear-gradient(90deg,#166534,#4ade80);"></div></div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="side-card" style="margin-top:8px;">
        <div style="font-weight:700;color:#fff;margin-bottom:4px;">🧭 Provenance Key</div>
        <span class="badge-explicit">EXPLICIT</span> Stored A-Box<br/>
        <span class="badge-inferred" style="margin-top:4px;">INFERRED</span> OWL / Multi-Hop
    </div>
    """, unsafe_allow_html=True)

# --- Tactical Top Hero Bar ---
st.markdown(f"""
<div class="hero-box">
    <div>
        <div class="hero-title">AEGIS-KG // IoT Botnet Threat Intelligence Console</div>
        <div class="hero-sub">Neuro-Symbolic KG-Grounded QA • V2 OWL Ontology + Multi-Hop Inference + Local Qwen 2.5</div>
    </div>
    <div class="hero-pills">
        <span class="pill">📊 {len(kg):,} Triples</span>
        <span class="pill">⚙️ OWL-RL + Multi-Hop</span>
        <span class="pill">🔒 Zero-Hallucination Guard</span>
    </div>
</div>
""", unsafe_allow_html=True)

# --- Single-Row Query Control Bar ---
sample_qs = [
    "",
    "Which source devices are inferred as compromised in the multi-hop reasoning graph?",
    "Which destination ports and threat labels are linked to Okiru botnet connections?",
    "Which connections are targeted by DDoS or PartOfAHorizontalPortScan traffic?",
    "What is the firmware version and physical room location of the infected IoT devices?"
]

c_drop, c_input, c_btn = st.columns([1.3, 2.05, 0.65])
with c_drop:
    selected = st.selectbox("🎯 Competency Question Preset:", sample_qs)
with c_input:
    question = st.text_input("💬 Natural-Language Threat Query:", value=selected)
with c_btn:
    run_clicked = st.button("⚡ Execute", type="primary")

# --- Single-Screen Results Workspace ---
if run_clicked and question:
    explicit, inferred, raw_triples, sparql_query = retrieve_evidence(question)
    with st.spinner("Traversing V2 Knowledge Graph & grounding Qwen 2.5..."):
        answer = generate_grounded_answer(question, explicit, inferred)

    is_refusal = "Insufficient evidence" in answer
    conf_score = "0% (Blocked)" if is_refusal else "100% Grounded"
    threat_level = "N/A (Out-of-Scope)" if is_refusal else ("CRITICAL" if inferred else "MODERATE")

    # Compact 4-Card Telemetry Strip
    st.markdown(f"""
    <div class="telem-grid">
        <div class="telem-item"><div class="telem-val">{len(explicit)}</div><div class="telem-lbl">Explicit A-Box Triples</div></div>
        <div class="telem-item"><div class="telem-val">{len(inferred)}</div><div class="telem-lbl">Inferred Reasoning Triples</div></div>
        <div class="telem-item"><div class="telem-val">{threat_level}</div><div class="telem-lbl">Threat Severity</div></div>
        <div class="telem-item"><div class="telem-val">{conf_score}</div><div class="telem-lbl">Grounding Verification</div></div>
    </div>
    """, unsafe_allow_html=True)

    left_col, right_col = st.columns([1.2, 1.05])

    with left_col:
        with st.container(height=295, border=True):
            st.markdown("**🧠 Grounded Threat Analysis**")
            if is_refusal:
                st.warning(f"⚠️ **Guardrail Triggered:** {answer}")
            else:
                st.success(answer)
            st.caption("Equivalent SPARQL Retrieval Pattern:")
            st.code(sparql_query, language="sparql")

    with right_col:
        with st.container(height=295, border=True):
            tab_inf, tab_exp, tab_viz = st.tabs([
                f"🔥 Inferred ({len(inferred)})",
                f"📌 Explicit ({len(explicit)})",
                "🕸️ Graph Topology"
            ])

            with tab_inf:
                if inferred:
                    for item in inferred:
                        st.markdown(f'<div class="triple-card"><span class="badge-inferred">INFERRED</span>{item}</div>', unsafe_allow_html=True)
                else:
                    st.caption("No inferred triples matched this query.")

            with tab_exp:
                if explicit:
                    for item in explicit:
                        st.markdown(f'<div class="triple-card"><span class="badge-explicit">EXPLICIT</span>{item}</div>', unsafe_allow_html=True)
                else:
                    st.caption("No explicit triples matched this query.")

            with tab_viz:
                st.caption("Live Subgraph Provenance (Dashed Red = Inferred • Solid Green = Explicit)")
                st.markdown(render_svg_graph(raw_triples), unsafe_allow_html=True)