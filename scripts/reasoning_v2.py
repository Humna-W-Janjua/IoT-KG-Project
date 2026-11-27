
from rdflib import Graph, Namespace, RDF, RDFS, Literal, URIRef
from pathlib import Path

# Project paths
BASE = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE / "RDF_Knowledge_Graph"
    / "iot_knowledge_graph_v2.ttl"
)

OUTPUT_FILE = (
    BASE / "RDF_Knowledge_Graph"
    / "iot_inferred_facts_v2.ttl"
)

# Namespaces
IOT = Namespace("http://example.org/iot#")
PROV = Namespace("http://www.w3.org/ns/prov#")

# Load original knowledge graph
kg = Graph()
kg.parse(str(INPUT_FILE), format="turtle")

# Store only newly inferred facts separately
inferred = Graph()

inferred.bind("iot", IOT)
inferred.bind("prov", PROV)
inferred.bind("rdf", RDF)

# Inference statistics
malicious_count = 0
benign_count = 0

print("=" * 65)
print("ITERATION 2 | SYMBOLIC REASONING")
print("=" * 65)

# Process every connection
connections = list(kg.subjects(RDF.type, IOT.NetworkConnection))

for connection in connections:

    # Find the explicit traffic label node
    label_nodes = list(
        kg.objects(connection, IOT.hasTrafficLabel)
    )

    if len(label_nodes) != 1:
        print(
            "[WARNING] Expected one label for:",
            connection
        )
        continue

    label_node = label_nodes[0]

    # Read the human-readable label
    label_name = kg.value(label_node, RDFS.label)

    if label_name is None:
        print(
            "[WARNING] Missing label name:",
            label_node
        )
        continue

    label_name = str(label_name)

    # Rule 1: classify connection using its explicit label
    if label_name == "Benign":

        inferred.add((
            connection,
            RDF.type,
            IOT.BenignConnection
        ))

        benign_count += 1

    else:

        inferred.add((
            connection,
            RDF.type,
            IOT.MaliciousConnection
        ))

        # Record the evidence used by the rule
        inferred.add((
            connection,
            PROV.wasDerivedFrom,
            label_node
        ))

        malicious_count += 1

# Save inferred facts separately
inferred.serialize(
    destination=str(OUTPUT_FILE),
    format="turtle"
)

print("\n========== REASONING RESULTS ==========")

print("Total connections:", len(connections))
print("Malicious connections inferred:", malicious_count)
print("Benign connections inferred:", benign_count)

print("\n========== INFERENCE RULE ==========")
print("If traffic label is Benign:")
print("    Infer BenignConnection")
print("Otherwise:")
print("    Infer MaliciousConnection")

print("\n========== VALIDATION ==========")

print(
    "Expected malicious connections: 1998"
)
print(
    "Expected benign connections: 1"
)

print(
    "Malicious count correct:",
    malicious_count == 1998
)

print(
    "Benign count correct:",
    benign_count == 1
)

print(
    "Inferred triples:",
    len(inferred)
)

print("\nInferred facts saved to:")
print(OUTPUT_FILE)

print("\n" + "=" * 65)
print("SYMBOLIC REASONING COMPLETED")
print("=" * 65)
