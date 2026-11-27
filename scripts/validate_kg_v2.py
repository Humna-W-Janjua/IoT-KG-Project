
from rdflib import Graph, Namespace, RDF, RDFS, OWL, URIRef
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

ontology_file = BASE / "Ontology" / "ontology_v2.ttl"
graph_file = BASE / "RDF_Knowledge_Graph" / "iot_knowledge_graph_v2.ttl"

IOT = Namespace("http://example.org/iot#")

# Load ontology and knowledge graph separately
ontology = Graph()
ontology.parse(str(ontology_file), format="turtle")

kg = Graph()
kg.parse(str(graph_file), format="turtle")

print("=" * 65)
print("ITERATION 2 | KNOWLEDGE GRAPH VALIDATION")
print("=" * 65)

print("\n1. FILE VALIDATION")
print("Ontology loaded:", len(ontology), "triples")
print("Knowledge graph loaded:", len(kg), "triples")

# Count RDF types
type_counts = Counter(kg.objects(None, RDF.type))

print("\n2. ENTITY TYPE COUNTS")
for entity_type, count in type_counts.items():
    print(f"{entity_type}: {count}")

# Count predicates
predicate_counts = Counter(kg.predicates())

print("\n3. PREDICATE COUNTS")
for predicate, count in predicate_counts.items():
    print(f"{predicate}: {count}")

# Check label values
print("\n4. THREAT LABEL VALUES")

label_values = set()

for predicate, obj in kg.subject_objects():
    if "label" in str(predicate).lower():
        label_values.add(str(obj))

for label in sorted(label_values):
    print(label)

print("Distinct label values:", len(label_values))

# Check ontology classes
print("\n5. ONTOLOGY CLASSES")

for cls in sorted(ontology.subjects(RDF.type, OWL.Class), key=str):
    print(cls)

print("\n6. ONTOLOGY PROPERTIES")

for prop in sorted(
    set(ontology.subjects(RDF.type, OWL.ObjectProperty))
    | set(ontology.subjects(RDF.type, OWL.DatatypeProperty)),
    key=str
):
    print(prop)

print("\n7. BASIC VALIDATION")

connection_class = IOT.NetworkConnection

connections = set(kg.subjects(RDF.type, connection_class))

print("NetworkConnection entities:", len(connections))
print("Expected connection entities: 1999")
print("Connection count correct:", len(connections) == 1999)

print("\n8. CONNECTION PROPERTY COMPLETENESS")

# Show predicates that are attached to connection entities
connection_predicates = Counter()

for connection in connections:
    for predicate in kg.predicates(connection, None):
        connection_predicates[predicate] += 1

for predicate, count in connection_predicates.items():
    print(f"{predicate}: present on {count} connections")

print("\n" + "=" * 65)
print("VALIDATION INSPECTION COMPLETE")
print("=" * 65)
