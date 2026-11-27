"""
IoT-KG-Project: Step 1 implementation audit
Run from the repository root:
    python scripts/audit_project.py
"""
from pathlib import Path
from collections import Counter
import sys

try:
    import pandas as pd
    from rdflib import Graph, Namespace, RDF, OWL, RDFS
    from rdflib.plugins.sparql.parser import parseQuery
except ImportError as exc:
    print(f"Missing dependency: {exc}")
    print("Activate your virtual environment and run: pip install pandas rdflib")
    raise SystemExit(1)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "Dataset" / "iot23_sample.csv"
ONTOLOGY = ROOT / "Ontology" / "ontology.owl"
RDF_FILE = ROOT / "RDF_Knowledge_Graph" / "iot_knowledge_graph.ttl"
QUERIES = ROOT / "SPARQL_Queries" / "queries.txt"
RESULTS = ROOT / "Results"

IOT = Namespace("http://example.org/iot#")

def status(label, ok, detail=""):
    mark = "PASS" if ok else "CHECK"
    print(f"[{mark}] {label}" + (f": {detail}" if detail else ""))

def main():
    print("=" * 68)
    print("IoT-KG PROJECT | STEP 1 BASELINE AUDIT")
    print("=" * 68)
    print(f"Repository: {ROOT}")
    print(f"Python: {sys.version.split()[0]}")
    print()

    required = [DATA, ONTOLOGY, RDF_FILE, QUERIES]
    for path in required:
        status(f"File exists - {path.relative_to(ROOT)}", path.exists())
    if not all(p.exists() for p in required):
        print("\nFix missing files before continuing.")
        raise SystemExit(2)

    # Dataset audit
    df = pd.read_csv(DATA)
    print("\n--- DATASET ---")
    status("Dataset loaded", True, f"{len(df):,} rows x {len(df.columns)} columns")
    print("Columns:", ", ".join(map(str, df.columns)))
    required_cols = {"id.orig_h", "id.resp_h", "id.resp_p", "proto", "label"}
    status("Required network fields present", required_cols.issubset(df.columns),
           f"missing={sorted(required_cols - set(df.columns))}")
    if "label" in df.columns:
        print("Label distribution:")
        for label, count in df["label"].value_counts(dropna=False).items():
            print(f"  {label}: {count}")
    if "id.orig_h" in df.columns:
        print("Unique source IPs:", df["id.orig_h"].nunique(dropna=True))
    if "id.resp_h" in df.columns:
        print("Unique destination IPs:", df["id.resp_h"].nunique(dropna=True))

    # RDF audit
    print("\n--- RDF GRAPH ---")
    graph = Graph()
    graph.parse(RDF_FILE, format="turtle")
    print("Triple count:", f"{len(graph):,}")
    print("Predicate counts:")
    for predicate, count in Counter(str(p) for _, p, _ in graph).most_common():
        print(f"  {predicate}: {count}")
    type_counts = Counter(str(o) for _, _, o in graph.triples((None, RDF.type, None)))
    print("Explicit rdf:type counts:")
    for class_uri, count in type_counts.items():
        print(f"  {class_uri}: {count}")
    print("Explicit Device instances:", len(set(graph.subjects(RDF.type, IOT.Device))))
    print("Explicit NetworkNode instances:", len(set(graph.subjects(RDF.type, IOT.NetworkNode))))
    print("Threat-label assertions:", len(list(graph.triples((None, IOT.hasThreatLabel, None)))))
    print("Distinct threat labels:", sorted({str(o) for _, _, o in graph.triples((None, IOT.hasThreatLabel, None))}))

    # Ontology audit
    print("\n--- ONTOLOGY ---")
    ontology_graph = Graph()
    ontology_graph.parse(ONTOLOGY)
    classes = sorted(str(s) for s in ontology_graph.subjects(RDF.type, OWL.Class))
    properties = sorted(str(s) for s in ontology_graph.subjects(RDF.type, OWL.ObjectProperty))
    data_properties = sorted(str(s) for s in ontology_graph.subjects(RDF.type, OWL.DatatypeProperty))
    print("OWL classes:")
    for item in classes:
        print(" ", item)
    print("Object properties:")
    for item in properties:
        print(" ", item)
    print("Datatype properties:")
    for item in data_properties:
        print(" ", item)
    print("Ontology triple count:", len(ontology_graph))

    # SPARQL audit
    print("\n--- SPARQL ---")
    query_text = QUERIES.read_text(encoding="utf-8")
    chunks = []
    current = []
    for line in query_text.splitlines():
        if line.strip().lower().startswith("#q") and current:
            chunks.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)
    if current:
        chunks.append("\n".join(current).strip())
    chunks = [chunk for chunk in chunks if "SELECT" in chunk.upper() or "ASK" in chunk.upper() or "CONSTRUCT" in chunk.upper()]
    print("Queries found:", len(chunks))
    for index, query in enumerate(chunks, 1):
        try:
            parseQuery(query)
            print(f"  Q{index}: syntax parsed")
        except Exception as exc:
            print(f"  Q{index}: PARSE ERROR - {exc}")

    print("\n--- RESULT FILES ---")
    result_files = sorted(RESULTS.glob("*.csv")) if RESULTS.exists() else []
    print("CSV result files:", len(result_files))
    for path in result_files:
        try:
            result_df = pd.read_csv(path)
            print(f"  {path.name}: {len(result_df)} rows, {len(result_df.columns)} columns")
        except Exception as exc:
            print(f"  {path.name}: could not read ({exc})")

    print("\n--- BASELINE NOTES ---")
    print("* This audit reads files; it does not modify the dataset, ontology, RDF, or query files.")
    print("* RDF triple count is for the Turtle A-Box file only, not the separate OWL ontology.")
    print("* Inference must be verified in the configured GraphDB repository; this script does not claim inferred facts.")
    print("* Review any CHECK items before proceeding to the next implementation phase.")
    print("=" * 68)

if __name__ == "__main__":
    main()
