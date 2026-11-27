# AEGIS-KG: Knowledge-Grounded IoT Botnet Detection & Threat Intelligence

**Course:** Knowledge Representation and Reasoning (KRR) — Fall 2026 (FAST-NUCES Islamabad)  
**Repository:** `https://github.com/Humna-W-Janjua/IoT-KG-Project`

---

## 1. Project Overview
**AEGIS-KG** is a neuro-symbolic cybersecurity system built on the **IoT-23** network traffic dataset (`iot23_sample.csv`). It pairs a formal **OWL 2 ontology** and **multi-hop rule reasoner** (`46,093` total RDF triples) with a local **Qwen 2.5 (`qwen2.5:3b` via Ollama)** LLM grounded strictly in retrieved Knowledge Graph evidence to eliminate hallucinations during botnet threat investigation.

### Active Knowledge Graph Architecture (Iteration 2)
| Layer | File Path | Triples | Description |
| :--- | :--- | :---: | :--- |
| **T-Box Ontology (V2)** | `Ontology/ontology_v2.ttl` | 63 | OWL classes, object/datatype properties, domain/range restrictions, and inverse/transitive axioms |
| **A-Box Assertions (V2)** | `RDF_Knowledge_Graph/iot_knowledge_graph_v2.ttl` | 26,036 | Instantiated IoT devices, network connections, ports, protocols, and threat labels |
| **OWL Rule Inferences** | `RDF_Knowledge_Graph/iot_inferred_facts_v2.ttl` | 6,008 | Materialized OWL-RL and domain rule inferences |
| **Multi-Hop Inferences** | `RDF_Knowledge_Graph/iot_multihop_inferences_v2.ttl` | 13,986 | Derived multi-hop device compromise, destination port, and threat propagation paths |
| **Total Active KG** | **Combined V2 Graph** | **46,093** | Unified RDF graph loaded into `app.py` |

---

## 2. Repository Structure
```text
IoT-KG-Project/
├── Dataset/                  # Sampled IoT-23 network flow dataset (iot23_sample.csv)
├── Ontology/                 # V1 & V2 OWL/Turtle schemas (ontology_v2.ttl, ontology.owl)
├── RDF_Knowledge_Graph/      # V2 A-Box triples, inferred facts, and multi-hop reasoning TTLs
├── Results/                  # 10-CQ LLM-only vs. KG-grounded benchmark (cq_10_evaluation.csv)
├── SPARQL_Queries/           # Competency Question SPARQL queries (CQ-01 to CQ-15)
├── Visualization/            # AEGIS-KG dashboard screenshots, provenance traces & ontology diagrams
├── scripts/                  # KG construction, validation, multi-hop reasoning & audit scripts
├── app.py                    # AEGIS-KG Streamlit cyber-SOC QA dashboard + SVG topology viewer
├── evaluate_10_cqs.py        # Automated 10-CQ evaluation script (Condition A vs. Condition B)
└── README.md                 # Project documentation & setup guide
