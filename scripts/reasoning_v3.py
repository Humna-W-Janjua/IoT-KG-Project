
from rdflib import Graph, Namespace, RDF, RDFS, OWL, Literal
from collections import defaultdict
from pathlib import Path

# --------------------------------------------------
# 1. PATHS AND NAMESPACES
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

ONTOLOGY_FILE = BASE_DIR / "Ontology" / "ontology_v2.ttl"
KG_FILE = BASE_DIR / "RDF_Knowledge_Graph" / "iot_knowledge_graph_v2.ttl"
INFERRED_FILE = BASE_DIR / "RDF_Knowledge_Graph" / "iot_inferred_facts_v2.ttl"

IOT = Namespace("http://example.org/iot#")
PROV = Namespace("http://www.w3.org/ns/prov#")

# --------------------------------------------------
# 2. LOAD EXISTING FILES
# --------------------------------------------------

ontology = Graph()
ontology.parse(ONTOLOGY_FILE, format="turtle")

kg = Graph()
kg.parse(KG_FILE, format="turtle")

inferred = Graph()
inferred.bind("iot", IOT)
inferred.bind("prov", PROV)
inferred.bind("rdf", RDF)
inferred.bind("rdfs", RDFS)

print("Ontology loaded:", len(ontology), "triples")
print("Knowledge graph loaded:", len(kg), "triples")

# --------------------------------------------------
# 3. ADD NEW ONTOLOGY CLASSES
# --------------------------------------------------

new_classes = [
    (IOT.RepeatedDestinationPort,
     "Repeated Destination Port",
     "A destination port targeted by two or more connections."),

    (IOT.ThreatAssociatedPort,
     "Threat Associated Port",
     "A destination port targeted by at least one malicious connection.")
]

for class_uri, label, description in new_classes:
    ontology.add((class_uri, RDF.type, OWL.Class))
    ontology.add((class_uri, RDFS.subClassOf, IOT.Port))
    ontology.add((class_uri, RDFS.label, Literal(label)))
    ontology.add((class_uri, RDFS.comment, Literal(description)))

ontology.serialize(ONTOLOGY_FILE, format="turtle")

# --------------------------------------------------
# 4. COLLECT CONNECTION INFORMATION
# --------------------------------------------------

connections = list(kg.subjects(RDF.type, IOT.NetworkConnection))

port_connections = defaultdict(list)
port_malicious_connections = defaultdict(list)

malicious_count = 0
benign_count = 0

# --------------------------------------------------
# 5. RULE 1: TRAFFIC CLASSIFICATION
# --------------------------------------------------

for connection in connections:

    labels = list(kg.objects(connection, IOT.hasTrafficLabel))

    if not labels:
        continue

    label_node = labels[0]
    label_values = list(kg.objects(label_node, RDFS.label))

    if not label_values:
        continue

    label = str(label_values[0])

    if label == "Benign":
        inferred.add((connection, RDF.type, IOT.BenignConnection))
        benign_count += 1
    else:
        inferred.add((connection, RDF.type, IOT.MaliciousConnection))
        malicious_count += 1

    # Record the evidence behind the classification.
    inferred.add((connection, PROV.wasDerivedFrom, label_node))

    # Collect destination port relationships.
    destination_ports = list(
        kg.objects(connection, IOT.hasDestinationPort)
    )

    for port in destination_ports:
        port_connections[port].append(connection)

        if label != "Benign":
            port_malicious_connections[port].append(connection)

# --------------------------------------------------
# 6. RULE 2: REPEATED DESTINATION PORT
# --------------------------------------------------

repeated_ports = 0

for port, related_connections in port_connections.items():

    if len(related_connections) >= 2:

        inferred.add((port, RDF.type, IOT.RepeatedDestinationPort))

        # Preserve evidence from the connections.
        for connection in related_connections:
            inferred.add((port, PROV.wasDerivedFrom, connection))

        repeated_ports += 1

# --------------------------------------------------
# 7. RULE 3: THREAT-ASSOCIATED PORT
# --------------------------------------------------

threat_ports = 0

for port, malicious_connections in port_malicious_connections.items():

    if len(malicious_connections) >= 1:

        inferred.add((port, RDF.type, IOT.ThreatAssociatedPort))

        # Preserve evidence from malicious connections.
        for connection in malicious_connections:
            inferred.add((port, PROV.wasDerivedFrom, connection))

        threat_ports += 1

# --------------------------------------------------
# 8. SAVE INFERRED FACTS
# --------------------------------------------------

inferred.serialize(INFERRED_FILE, format="turtle")

# --------------------------------------------------
# 9. DISPLAY RESULTS
# --------------------------------------------------

print("\n========== SYMBOLIC REASONING RESULTS ==========")

print("\nRULE 1: TRAFFIC CLASSIFICATION")
print("Malicious connections:", malicious_count)
print("Benign connections:", benign_count)
print("Total classified:", malicious_count + benign_count)

print("\nRULE 2: REPEATED DESTINATION PORT")
print("Repeated destination ports:", repeated_ports)

for port, related_connections in port_connections.items():
    if len(related_connections) >= 2:
        print(
            str(port).split("#")[-1],
            "->",
            len(related_connections),
            "connections"
        )

print("\nRULE 3: THREAT-ASSOCIATED PORT")
print("Threat-associated ports:", threat_ports)

for port, related_connections in port_malicious_connections.items():
    if related_connections:
        print(
            str(port).split("#")[-1],
            "->",
            len(related_connections),
            "malicious connections"
        )

print("\n========== FINAL VALIDATION ==========")

print("Total original connections:", len(connections))
print("Total inferred triples:", len(inferred))

print(
    "All connections classified:",
    malicious_count + benign_count == len(connections)
)

print(
    "Inferred classifications are mutually exclusive:",
    not any(
        (connection, RDF.type, IOT.BenignConnection) in inferred
        and (connection, RDF.type, IOT.MaliciousConnection) in inferred
        for connection in connections
    )
)

print("\nOntology updated:", ONTOLOGY_FILE)
print("Inferred facts saved:", INFERRED_FILE)
print("\n[COMPLETED] Three symbolic reasoning rules executed.")
