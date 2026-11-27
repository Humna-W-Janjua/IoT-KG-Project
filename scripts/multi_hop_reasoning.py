
from rdflib import Graph, Namespace, RDF, RDFS, OWL, Literal, URIRef
from pathlib import Path

# --------------------------------------------------
# 1. FILE PATHS AND NAMESPACES
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

ONTOLOGY_FILE = BASE_DIR / "Ontology" / "ontology_v2.ttl"
KG_FILE = BASE_DIR / "RDF_Knowledge_Graph" / "iot_knowledge_graph_v2.ttl"
INFERRED_FILE = BASE_DIR / "RDF_Knowledge_Graph" / "iot_inferred_facts_v2.ttl"

MULTIHOP_FILE = BASE_DIR / "RDF_Knowledge_Graph" / "iot_multihop_inferences_v2.ttl"

IOT = Namespace("http://example.org/iot#")
PROV = Namespace("http://www.w3.org/ns/prov#")

# --------------------------------------------------
# 2. LOAD ONTOLOGY AND KNOWLEDGE GRAPH
# --------------------------------------------------

ontology = Graph()
ontology.parse(ONTOLOGY_FILE, format="turtle")

kg = Graph()
kg.parse(KG_FILE, format="turtle")

# Load the existing symbolic inferences.
inferred = Graph()
inferred.parse(INFERRED_FILE, format="turtle")

# Store new multi-hop conclusions separately.
multi_hop = Graph()
multi_hop.bind("iot", IOT)
multi_hop.bind("prov", PROV)
multi_hop.bind("rdf", RDF)
multi_hop.bind("rdfs", RDFS)

print("Ontology loaded:", len(ontology), "triples")
print("Knowledge graph loaded:", len(kg), "triples")
print("Existing inferred facts loaded:", len(inferred), "triples")

# --------------------------------------------------
# 3. DEFINE MULTI-HOP ONTOLOGY TERMS
# --------------------------------------------------

ontology.add((IOT.MultiHopInference, RDF.type, OWL.Class))
ontology.add((
    IOT.MultiHopInference,
    RDFS.label,
    Literal("Multi-Hop Inference")
))

ontology.add((
    IOT.hasMaliciouslyContacted,
    RDF.type,
    OWL.ObjectProperty
))
ontology.add((
    IOT.hasMaliciouslyContacted,
    RDFS.domain,
    IOT.Device
))
ontology.add((
    IOT.hasMaliciouslyContacted,
    RDFS.range,
    IOT.NetworkNode
))

# Evidence properties for each inference record.
evidence_properties = [
    IOT.evidenceConnection,
    IOT.inferredSourceDevice,
    IOT.inferredDestinationNode,
    IOT.inferredTrafficLabel,
    IOT.inferredDestinationPort
]

for prop in evidence_properties:
    ontology.add((prop, RDF.type, OWL.ObjectProperty))

ontology.serialize(ONTOLOGY_FILE, format="turtle")

# --------------------------------------------------
# 4. MULTI-HOP REASONING
# --------------------------------------------------

connections = list(kg.subjects(RDF.type, IOT.NetworkConnection))

malicious_paths = 0
benign_paths = 0
incomplete_paths = 0

source_devices = set()
destination_nodes = set()
traffic_labels = set()
destination_ports = set()

examples = []

for connection in connections:

    # First hop: connection -> source device
    sources = list(kg.objects(connection, IOT.initiatedBy))

    # Second hop: connection -> destination node
    destinations = list(kg.objects(connection, IOT.targets))

    # Third hop: connection -> traffic label
    labels = list(kg.objects(connection, IOT.hasTrafficLabel))

    # Additional hop: connection -> destination port
    ports = list(kg.objects(connection, IOT.hasDestinationPort))

    # Require all evidence for a complete path.
    if not sources or not destinations or not labels or not ports:
        incomplete_paths += 1
        continue

    source = sources[0]
    destination = destinations[0]
    label_node = labels[0]
    port = ports[0]

    label_values = list(kg.objects(label_node, RDFS.label))

    if not label_values:
        incomplete_paths += 1
        continue

    label = str(label_values[0])

    source_devices.add(source)
    destination_nodes.add(destination)
    traffic_labels.add(label)
    destination_ports.add(port)

    # Only infer malicious communication paths.
    if label == "Benign":
        benign_paths += 1
        continue

    malicious_paths += 1

    # Infer a new relationship between the source device
    # and destination node through the connection.
    multi_hop.add((
        source,
        IOT.hasMaliciouslyContacted,
        destination
    ))

    # Create a separate resource describing the inference
    # and recording all supporting evidence.
    connection_name = str(connection).split("#")[-1]

    inference = URIRef(
        str(IOT) + "MultiHopInference_" + connection_name
    )

    multi_hop.add((inference, RDF.type, IOT.MultiHopInference))
    multi_hop.add((inference, IOT.evidenceConnection, connection))
    multi_hop.add((inference, IOT.inferredSourceDevice, source))
    multi_hop.add((inference, IOT.inferredDestinationNode, destination))
    multi_hop.add((inference, IOT.inferredTrafficLabel, label_node))
    multi_hop.add((inference, IOT.inferredDestinationPort, port))

    if len(examples) < 5:
        examples.append({
            "connection": connection_name,
            "source": str(source).split("#")[-1],
            "destination": str(destination).split("#")[-1],
            "label": label,
            "port": str(port).split("#")[-1]
        })

# --------------------------------------------------
# 5. SAVE MULTI-HOP INFERENCES
# --------------------------------------------------

multi_hop.serialize(MULTIHOP_FILE, format="turtle")

# --------------------------------------------------
# 6. DISPLAY RESULTS
# --------------------------------------------------

print("\n========== MULTI-HOP REASONING RESULTS ==========")

print("Total connections examined:", len(connections))
print("Malicious paths:", malicious_paths)
print("Benign paths:", benign_paths)
print("Incomplete paths:", incomplete_paths)

print("\nDistinct source devices:", len(source_devices))
print("Distinct destination nodes:", len(destination_nodes))
print("Distinct traffic labels:", len(traffic_labels))
print("Distinct destination ports:", len(destination_ports))

print("\n========== SAMPLE MULTI-HOP RESULTS ==========")

for i, example in enumerate(examples, start=1):
    print(f"\nExample {i}")
    print("Connection:", example["connection"])
    print("Source device:", example["source"])
    print("Destination node:", example["destination"])
    print("Traffic label:", example["label"])
    print("Destination port:", example["port"])

print("\n========== FINAL VALIDATION ==========")

inference_records = set(
    multi_hop.subjects(RDF.type, IOT.MultiHopInference)
)

malicious_relations = set(
    multi_hop.subject_objects(IOT.hasMaliciouslyContacted)
)

evidence_count = sum(
    1 for _ in multi_hop.subject_objects(IOT.evidenceConnection)
)

print("Expected malicious paths:", 1998)
print("Actual malicious paths:", malicious_paths)
print("Inference records:", len(inference_records))
print("Inferred device-destination relationships:", len(malicious_relations))
print("Evidence connection links:", evidence_count)

print(
    "[PASS] All malicious paths processed."
    if malicious_paths == 1998
    else "[WARNING] Malicious path count differs."
)

print(
    "[PASS] Every malicious path has an inference record."
    if len(inference_records) == malicious_paths
    else "[WARNING] Some inference records are missing."
)

print(
    "[PASS] Every inference record has evidence."
    if evidence_count == malicious_paths
    else "[WARNING] Some evidence links are missing."
)

print("\nOntology updated:", ONTOLOGY_FILE)
print("Multi-hop results saved:", MULTIHOP_FILE)

print("\n[COMPLETED] Multi-hop reasoning executed.")
