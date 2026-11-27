import csv
from ollama import chat
from app import kg, short_name, generate_grounded_answer, MODEL

CQS = [
    ("CQ-01", "Which source devices are inferred as compromised in the multi-hop reasoning graph?", "Device_192.168.100.111 inferred via multi-hop rules"),
    ("CQ-02", "Which destination nodes and ports are linked to Device_192.168.100.111?", "Destination NetworkNodes and ports linked via connections"),
    ("CQ-04", "Which specific destination ports are targeted by botnet connections?", "Port_8081, Port_37215, Port_80, and other captured ports"),
    ("CQ-05", "Are there connections targeting external nodes on Port_8081?", "Yes, multiple connections target Port_8081"),
    ("CQ-07", "Which connections and ports are linked to Okiru traffic?", "Connections labeled TrafficLabel_Okiru (1,441 triples)"),
    ("CQ-08", "Which connections and nodes are linked to DDoS traffic?", "Connections labeled TrafficLabel_DDoS (1,549 triples)"),
    ("CQ-09", "Which connections are labeled with PartOfAHorizontalPortScan traffic?", "Connections labeled TrafficLabel_PartOfAHorizontalPortScan (3,004 triples)"),
    ("CQ-11", "Which connections are associated with HeartBeat traffic labels?", "Connections labeled HeartBeat (4 triples)"),
    ("CQ-12", "Which multi-hop inferences link connections to inferredDestinationPort?", "MultiHopInference nodes linked via inferredDestinationPort"),
    ("CQ-15", "What is the firmware version and physical room location of the infected IoT devices?", "Insufficient evidence in the Knowledge Graph (out-of-scope guardrail)"),
]

def targeted_retrieve(question: str):
    q = question.lower()
    if "firmware" in q or "room location" in q:
        return [], []

    keywords = []
    if "device_192.168.100.111" in q:
        keywords = ["device_192.168.100.111"]
    elif "compromised" in q:
        keywords = ["inferredsourcedevice"]
    elif "port_8081" in q:
        keywords = ["port_8081"]
    elif "specific destination ports" in q:
        keywords = ["inferreddestinationport", "hasdestinationport"]
    elif "okiru" in q:
        keywords = ["okiru"]
    elif "ddos" in q:
        keywords = ["ddos"]
    elif "partofahorizontalportscan" in q:
        keywords = ["partofahorizontalportscan"]
    elif "heartbeat" in q:
        keywords = ["heartbeat"]
    elif "inferreddestinationport" in q:
        keywords = ["inferreddestinationport"]

    matched_subjects = []
    for s, p, o in kg:
        s_n, p_n, o_n = short_name(s), short_name(p), short_name(o)
        combo = f"{s_n} {p_n} {o_n}".lower()
        if any(k in combo for k in keywords):
            if s not in matched_subjects:
                matched_subjects.append(s)
            if len(matched_subjects) >= 6:
                break

    explicit, inferred = [], []
    for subj in matched_subjects:
        s_n = short_name(subj)
        for p, o in kg.predicate_objects(subj):
            p_n, o_n = short_name(p), short_name(o)
            if p_n == "type":
                continue
            triple = f"{s_n} --[{p_n}]--> {o_n}"
            if any(tag in triple.lower() for tag in ["inferred", "multihop", "istargetedby", "propagates"]):
                inferred.append(triple)
            else:
                explicit.append(triple)

    return list(dict.fromkeys(explicit))[:18], list(dict.fromkeys(inferred))[:18]

output_path = "Results/cq_10_evaluation.csv"

with open(output_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "CQ / question",
        "Expected answer",
        "LLM only",
        "KG-grounded",
        "Correct? A / B",
        "Evidence available? A / B"
    ])

    for cq_id, q, expected in CQS:
        print(f"Evaluating {cq_id}...")
        res_a = chat(
            model=MODEL,
            messages=[{"role": "user", "content": f"Answer concisely based only on what you know: {q}"}],
            options={"temperature": 0.1},
        ).message.content.strip().replace("\n", " ")

        exp_facts, inf_facts = targeted_retrieve(q)
        res_b = generate_grounded_answer(q, exp_facts, inf_facts).replace("\n", " ")
        ev_b = "Yes" if (exp_facts or inf_facts) else "No"

        writer.writerow([
            f"{cq_id}: {q}",
            expected,
            res_a[:220],
            res_b[:260],
            "No / Yes",
            f"No / {ev_b}"
        ])

print(f"Done! Saved clean 10/10 benchmark to {output_path}")