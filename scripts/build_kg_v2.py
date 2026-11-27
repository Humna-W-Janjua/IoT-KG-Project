"""
Iteration 2 - Build a connection-centric IoT Knowledge Graph.

Input:
    Dataset/processed/iot23_clean.csv (preferred, if it exists)
    otherwise Dataset/iot23_sample.csv

Outputs:
    Ontology/ontology_v2.ttl
    RDF_Knowledge_Graph/iot_knowledge_graph_v2.ttl

This script does not modify the original CSV, ontology, or RDF graph.
"""

from pathlib import Path
from decimal import Decimal
import re
from urllib.parse import quote

import pandas as pd
from rdflib import Graph, Namespace, URIRef, Literal, RDF, RDFS, OWL, XSD


BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_CSV = BASE_DIR / "Dataset" / "processed" / "iot23_clean.csv"
ORIGINAL_CSV = BASE_DIR / "Dataset" / "iot23_sample.csv"

ONTOLOGY_OUTPUT = BASE_DIR / "Ontology" / "ontology_v2.ttl"
GRAPH_OUTPUT = BASE_DIR / "RDF_Knowledge_Graph" / "iot_knowledge_graph_v2.ttl"

IOT = Namespace("http://example.org/iot#")


def safe_name(value):
    """Create a stable URI-friendly name from a value."""
    return quote(str(value).strip(), safe="")


def label_slug(value):
    """Create a readable URI suffix for a traffic label."""
    slug = re.sub(r"[^A-Za-z0-9]+", "_", str(value).strip()).strip("_")
    return slug or "Unknown"


def build_ontology():
    """Create the Iteration 2 schema (T-Box) as Turtle."""
    g = Graph()
    g.bind("iot", IOT)
    g.bind("owl", OWL)
    g.bind("rdfs", RDFS)
    g.bind("xsd", XSD)

    # Classes
    classes = [
        IOT.Device,
        IOT.NetworkNode,
        IOT.NetworkConnection,
        IOT.Port,
        IOT.Protocol,
        IOT.TrafficLabel,
        IOT.MaliciousConnection,
        IOT.BenignConnection,
    ]
    for cls in classes:
        g.add((cls, RDF.type, OWL.Class))

    g.add((IOT.MaliciousConnection, RDFS.subClassOf, IOT.NetworkConnection))
    g.add((IOT.BenignConnection, RDFS.subClassOf, IOT.NetworkConnection))

    # Object properties
    object_properties = {
        IOT.initiatedBy: (IOT.NetworkConnection, IOT.Device),
        IOT.targets: (IOT.NetworkConnection, IOT.NetworkNode),
        IOT.hasSourcePort: (IOT.NetworkConnection, IOT.Port),
        IOT.hasDestinationPort: (IOT.NetworkConnection, IOT.Port),
        IOT.usesProtocol: (IOT.NetworkConnection, IOT.Protocol),
        IOT.hasTrafficLabel: (IOT.NetworkConnection, IOT.TrafficLabel),
    }

    for prop, (domain, range_) in object_properties.items():
        g.add((prop, RDF.type, OWL.ObjectProperty))
        g.add((prop, RDFS.domain, domain))
        g.add((prop, RDFS.range, range_))

    # Datatype properties
    datatype_properties = {
        IOT.ipAddress: (None, XSD.string),
        IOT.durationSeconds: (IOT.NetworkConnection, XSD.decimal),
        IOT.timestampUnix: (IOT.NetworkConnection, XSD.integer),
        IOT.portNumber: (IOT.Port, XSD.integer),
        IOT.protocolName: (IOT.Protocol, XSD.string),
    }

    for prop, (domain, range_) in datatype_properties.items():
        g.add((prop, RDF.type, OWL.DatatypeProperty))
        if domain is not None:
            g.add((prop, RDFS.domain, domain))
        g.add((prop, RDFS.range, range_))

    g.add((
        IOT.NetworkConnection,
        RDFS.comment,
        Literal("Represents one individual connection record from the supplied sample dataset.")
    ))
    g.add((
        IOT.TrafficLabel,
        RDFS.comment,
        Literal("A dataset label. This class includes both malicious labels and Benign.")
    ))
    g.add((
        IOT.MaliciousConnection,
        RDFS.comment,
        Literal("A connection classified as malicious by an explicit reasoning rule or validated assertion.")
    ))

    return g


def main():
    input_file = PROCESSED_CSV if PROCESSED_CSV.exists() else ORIGINAL_CSV
    if not input_file.exists():
        raise FileNotFoundError(
            f"Could not find the sample CSV at either:\n{PROCESSED_CSV}\n{ORIGINAL_CSV}"
        )

    df = pd.read_csv(input_file)

    required = [
        "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "duration", "ts", "label"
    ]
    missing_columns = [column for column in required if column not in df.columns]
    if missing_columns:
        raise ValueError(f"Missing required columns: {missing_columns}")

    # Remove only the exported index column, if it is present.
    if "Unnamed: 0" in df.columns:
        df = df.drop(columns=["Unnamed: 0"])

    # Validate before constructing any graph.
    if df[required].isnull().any().any():
        raise ValueError("Required fields contain missing values. Inspect the CSV first.")
    if not df["uid"].is_unique:
        raise ValueError("Connection UID values are not unique; do not build until investigated.")

    df["id.orig_p"] = pd.to_numeric(df["id.orig_p"], errors="raise").astype(int)
    df["id.resp_p"] = pd.to_numeric(df["id.resp_p"], errors="raise").astype(int)
    df["duration"] = pd.to_numeric(df["duration"], errors="raise")
    df["ts"] = pd.to_numeric(df["ts"], errors="raise").astype(int)

    # Build the schema and instance graph separately.
    ontology = build_ontology()

    kg = Graph()
    kg.bind("iot", IOT)
    kg.bind("rdf", RDF)
    kg.bind("rdfs", RDFS)
    kg.bind("xsd", XSD)

    # Reusable source device (the sample currently has one unique source IP).
    source_ips = sorted(df["id.orig_h"].astype(str).str.strip().unique())
    for ip in source_ips:
        device = URIRef(IOT[f"Device_{safe_name(ip)}"])
        kg.add((device, RDF.type, IOT.Device))
        kg.add((device, IOT.ipAddress, Literal(ip, datatype=XSD.string)))
        kg.add((device, RDFS.label, Literal(f"Device {ip}")))

    # Create shared port, protocol, and label entities.
    all_ports = sorted(
        set(df["id.orig_p"].astype(int).tolist())
        | set(df["id.resp_p"].astype(int).tolist())
    )
    port_nodes = {}
    for port in all_ports:
        port_node = URIRef(IOT[f"Port_{port}"])
        port_nodes[port] = port_node
        kg.add((port_node, RDF.type, IOT.Port))
        kg.add((port_node, IOT.portNumber, Literal(port, datatype=XSD.integer)))
        kg.add((port_node, RDFS.label, Literal(f"Port {port}")))

    protocols = sorted(df["proto"].astype(str).str.strip().unique())
    protocol_nodes = {}
    for protocol in protocols:
        protocol_node = URIRef(IOT[f"Protocol_{safe_name(protocol.lower())}"])
        protocol_nodes[protocol] = protocol_node
        kg.add((protocol_node, RDF.type, IOT.Protocol))
        kg.add((protocol_node, IOT.protocolName, Literal(protocol, datatype=XSD.string)))
        kg.add((protocol_node, RDFS.label, Literal(protocol.upper())))

    labels = sorted(df["label"].astype(str).str.strip().unique())
    label_nodes = {}
    for traffic_label in labels:
        label_node = URIRef(IOT[f"TrafficLabel_{label_slug(traffic_label)}"])
        label_nodes[traffic_label] = label_node
        kg.add((label_node, RDF.type, IOT.TrafficLabel))
        kg.add((label_node, RDFS.label, Literal(traffic_label)))

    # One NetworkConnection entity for every CSV row.
    for _, row in df.iterrows():
        uid = str(row["uid"]).strip()
        source_ip = str(row["id.orig_h"]).strip()
        destination_ip = str(row["id.resp_h"]).strip()
        source_port = int(row["id.orig_p"])
        destination_port = int(row["id.resp_p"])
        protocol = str(row["proto"]).strip()
        traffic_label = str(row["label"]).strip()

        connection = URIRef(IOT[f"Connection_{safe_name(uid)}"])
        source_device = URIRef(IOT[f"Device_{safe_name(source_ip)}"])
        destination_node = URIRef(IOT[f"NetworkNode_{safe_name(destination_ip)}"])

        # Destination node
        kg.add((destination_node, RDF.type, IOT.NetworkNode))
        kg.add((destination_node, IOT.ipAddress, Literal(destination_ip, datatype=XSD.string)))
        kg.add((destination_node, RDFS.label, Literal(f"Network node {destination_ip}")))

        # Connection and its relationships
        kg.add((connection, RDF.type, IOT.NetworkConnection))
        kg.add((connection, IOT.initiatedBy, source_device))
        kg.add((connection, IOT.targets, destination_node))
        kg.add((connection, IOT.hasSourcePort, port_nodes[source_port]))
        kg.add((connection, IOT.hasDestinationPort, port_nodes[destination_port]))
        kg.add((connection, IOT.usesProtocol, protocol_nodes[protocol]))
        kg.add((connection, IOT.hasTrafficLabel, label_nodes[traffic_label]))

        # Numeric and timestamp attributes
        duration_value = Decimal(str(row["duration"]))
        kg.add((
            connection,
            IOT.durationSeconds,
            Literal(duration_value, datatype=XSD.decimal)
        ))
        kg.add((
            connection,
            IOT.timestampUnix,
            Literal(int(row["ts"]), datatype=XSD.integer)
        ))
        kg.add((connection, RDFS.label, Literal(f"Connection {uid}")))

    # Create output directories and save both files.
    ONTOLOGY_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    GRAPH_OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    ontology.serialize(destination=str(ONTOLOGY_OUTPUT), format="turtle")
    kg.serialize(destination=str(GRAPH_OUTPUT), format="turtle")

    # Parse saved files again to verify serialization.
    ontology_check = Graph().parse(str(ONTOLOGY_OUTPUT), format="turtle")
    kg_check = Graph().parse(str(GRAPH_OUTPUT), format="turtle")

    # Count the important entities in the saved graph.
    connection_count = len(set(kg_check.subjects(RDF.type, IOT.NetworkConnection)))
    device_count = len(set(kg_check.subjects(RDF.type, IOT.Device)))
    destination_count = len(set(kg_check.subjects(RDF.type, IOT.NetworkNode)))
    label_count = len(set(kg_check.subjects(RDF.type, IOT.TrafficLabel)))

    print("\n========== ITERATION 2 KNOWLEDGE GRAPH BUILD ==========")
    print("Input file:", input_file.relative_to(BASE_DIR))
    print("CSV records:", len(df))
    print("Unique connection UIDs:", df["uid"].nunique())
    print("Source devices:", device_count)
    print("Destination network nodes:", destination_count)
    print("NetworkConnection entities:", connection_count)
    print("TrafficLabel entities:", label_count)
    print("Distinct labels:", labels)
    print("Ontology triples:", len(ontology_check))
    print("Knowledge graph triples:", len(kg_check))
    print("Total triples across both files:", len(ontology_check) + len(kg_check))
    print("Ontology saved:", ONTOLOGY_OUTPUT.relative_to(BASE_DIR))
    print("Knowledge graph saved:", GRAPH_OUTPUT.relative_to(BASE_DIR))

    # Hard checks: these should hold for the supplied sample.
    assert len(df) == 1999, f"Expected 1999 rows, found {len(df)}"
    assert connection_count == len(df), "Not every CSV row became one connection."
    assert label_count == 5, f"Expected 5 labels, found {label_count}"
    assert destination_count == df["id.resp_h"].nunique()
    print("\n[PASS] Every input row has a separate connection entity.")
    print("[PASS] All five traffic labels, including Benign, are represented.")
    print("[PASS] Saved ontology and graph can be parsed again.")


if __name__ == "__main__":
    main()
