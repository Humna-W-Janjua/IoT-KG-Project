
from rdflib import Graph, Namespace, RDF, RDFS
from collections import Counter

# Namespaces
IOT = Namespace("http://example.org/iot#")

# Load inferred facts
g = Graph()
g.parse(
    "RDF_Knowledge_Graph/iot_inferred_facts_v2.ttl",
    format="turtle"
)

# Count inferred connection types
malicious = set(
    g.subjects(RDF.type, IOT.MaliciousConnection)
)

benign = set(
    g.subjects(RDF.type, IOT.BenignConnection)
)

# Count provenance sources
sources = Counter()

for connection, label in g.subject_objects(
    Namespace("http://www.w3.org/ns/prov#").wasDerivedFrom
):
    sources[str(label).split("#")[-1]] += 1

print("========== SYMBOLIC REASONING VALIDATION ==========")

print("Total inferred triples:", len(g))
print("Malicious connections:", len(malicious))
print("Benign connections:", len(benign))
print("Total classified connections:", len(malicious | benign))

print("\n========== PROVENANCE LABEL DISTRIBUTION ==========")

for label, count in sources.items():
    print(f"{label}: {count}")

print("\n========== VALIDATION ==========")

print("Expected total connections: 1999")
print("Actual classified connections:", len(malicious | benign))

if len(malicious | benign) == 1999:
    print("[PASS] All connections were classified.")
else:
    print("[WARNING] Classified connection count does not match.")

if malicious.isdisjoint(benign):
    print("[PASS] No connection belongs to both classes.")
else:
    print("[WARNING] Some connections belong to both classes.")
