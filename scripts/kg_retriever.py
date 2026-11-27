
from pathlib import Path
from rdflib import Graph, Namespace, RDF, RDFS
import re

# --------------------------------------------------
# 1. PROJECT PATHS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

KG_FILE = BASE_DIR / "RDF_Knowledge_Graph" / "iot_knowledge_graph_v2.ttl"

INFERRED_FILE = (
    BASE_DIR / "RDF_Knowledge_Graph" / "iot_inferred_facts_v2.ttl"
)

MULTIHOP_FILE = (
    BASE_DIR / "RDF_Knowledge_Graph" / "iot_multihop_inferences_v2.ttl"
)

IOT = Namespace("http://example.org/iot#")
PROV = Namespace("http://www.w3.org/ns/prov#")

# --------------------------------------------------
# 2. LOAD GRAPHS SEPARATELY
# --------------------------------------------------

kg = Graph()
kg.parse(KG_FILE, format="turtle")

inferred = Graph()
inferred.parse(INFERRED_FILE, format="turtle")

multihop = Graph()
multihop.parse(MULTIHOP_FILE, format="turtle")

print("Original KG triples:", len(kg))
print("Symbolic inference triples:", len(inferred))
print("Multi-hop inference triples:", len(multihop))


# --------------------------------------------------
# 3. HELPER FUNCTIONS
# --------------------------------------------------

def local_name(uri):
    """Extract the readable name from an RDF URI."""
    return str(uri).split("#")[-1]


def get_label(label_node):
    """Get the human-readable traffic label."""
    values = list(kg.objects(label_node, RDFS.label))
    return str(values[0]) if values else "Unknown"


def get_port_number(port_node):
    """Get the numeric port value."""
    values = list(kg.objects(port_node, IOT.portNumber))
    return str(values[0]) if values else "Unknown"


def get_connection_details(connection):
    """Retrieve explicit connection facts."""

    source_values = list(
        kg.objects(connection, IOT.initiatedBy)
    )

    destination_values = list(
        kg.objects(connection, IOT.targets)
    )

    label_values = list(
        kg.objects(connection, IOT.hasTrafficLabel)
    )

    port_values = list(
        kg.objects(connection, IOT.hasDestinationPort)
    )

    duration_values = list(
        kg.objects(connection, IOT.durationSeconds)
    )

    return {
        "connection": local_name(connection),
        "source": local_name(source_values[0]) if source_values else "Unknown",
        "destination": local_name(destination_values[0]) if destination_values else "Unknown",
        "label": get_label(label_values[0]) if label_values else "Unknown",
        "port": get_port_number(port_values[0]) if port_values else "Unknown",
        "duration": str(duration_values[0]) if duration_values else "Unknown"
    }


def get_all_connections():
    return list(kg.subjects(RDF.type, IOT.NetworkConnection))


# --------------------------------------------------
# 4. RETRIEVE CONNECTIONS BY TRAFFIC LABEL
# --------------------------------------------------

def retrieve_by_label(label, limit=10):

    results = []

    for connection in get_all_connections():

        details = get_connection_details(connection)

        if details["label"].lower() == label.lower():
            results.append(details)

            if len(results) >= limit:
                break

    return results


# --------------------------------------------------
# 5. RETRIEVE CONNECTIONS BY DESTINATION PORT
# --------------------------------------------------

def retrieve_by_port(port_number, limit=10):

    results = []

    for connection in get_all_connections():

        details = get_connection_details(connection)

        if details["port"] == str(port_number):
            results.append(details)

            if len(results) >= limit:
                break

    return results


# --------------------------------------------------
# 6. RETRIEVE A SPECIFIC CONNECTION
# --------------------------------------------------

def retrieve_by_connection(connection_id):

    for connection in get_all_connections():

        if local_name(connection).lower() == connection_id.lower():
            return [get_connection_details(connection)]

    return []


# --------------------------------------------------
# 7. GENERAL KNOWLEDGE GRAPH SUMMARY
# --------------------------------------------------

def retrieve_summary():

    label_counts = {}

    for label_node in kg.subjects(RDF.type, IOT.TrafficLabel):

        label = get_label(label_node)

        count = sum(
            1 for connection in get_all_connections()
            if label_node in kg.objects(
                connection, IOT.hasTrafficLabel
            )
        )

        label_counts[label] = count

    return {
        "total_connections": len(get_all_connections()),
        "label_distribution": label_counts,
        "source_devices": len(
            set(kg.subjects(RDF.type, IOT.Device))
        ),
        "destination_nodes": len(
            set(kg.subjects(RDF.type, IOT.NetworkNode))
        )
    }


# --------------------------------------------------
# 8. MAIN QUESTION RETRIEVAL FUNCTION
# --------------------------------------------------

def retrieve_context(question, limit=10):

    question_lower = question.lower()

    # Exact connection identifier.
    connection_match = re.search(
        r"connection_[a-zA-Z0-9]+",
        question,
        re.IGNORECASE
    )

    if connection_match:

        results = retrieve_by_connection(
            connection_match.group(0)
        )

        if results:
            return {
                "type": "connection",
                "evidence": results
            }

    # Traffic label search.
    labels = [
        "PartOfAHorizontalPortScan",
        "C&C-HeartBeat",
        "Benign",
        "DDoS",
        "Okiru"
    ]

    for label in labels:

        if label.lower() in question_lower:

            results = retrieve_by_label(label, limit)

            return {
                "type": "traffic_label",
                "label": label,
                "evidence": results
            }

    # Destination port search.
    port_match = re.search(
        r"\b(?:port\s*)?(\d{1,5})\b",
        question_lower
    )

    if port_match:

        port_number = port_match.group(1)

        results = retrieve_by_port(port_number, limit)

        return {
            "type": "destination_port",
            "port": port_number,
            "evidence": results
        }

    # General summary.
    return {
        "type": "summary",
        "evidence": retrieve_summary()
    }


# --------------------------------------------------
# 9. TEST THE RETRIEVER
# --------------------------------------------------

if __name__ == "__main__":

    test_questions = [
        "Show me DDoS connections",
        "Which connections use port 52869?",
        "Explain connection C02UbI2RngmvUpBAma",
        "Give me an overview of the IoT knowledge graph"
    ]

    for question in test_questions:

        print("\n" + "=" * 60)
        print("QUESTION:", question)

        result = retrieve_context(question)

        print("RETRIEVAL TYPE:", result["type"])
        print("RETRIEVED EVIDENCE:")

        print(result["evidence"])
