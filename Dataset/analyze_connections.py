
import pandas as pd

df = pd.read_csv("Dataset/iot23_sample.csv")

print("\n========== 1. THREAT LABELS AND DESTINATION PORTS ==========")
print(
    pd.crosstab(
        df["label"],
        df["id.resp_p"]
    ).to_string()
)

print("\n========== 2. THREAT LABELS AND SOURCE PORTS ==========")
print(
    pd.crosstab(
        df["label"],
        df["id.orig_p"]
    ).to_string()
)

print("\n========== 3. DURATION STATISTICS BY THREAT LABEL ==========")
print(
    df.groupby("label")["duration"]
    .agg(["count", "min", "mean", "median", "max"])
    .to_string()
)

print("\n========== 4. CONNECTION IDENTIFIERS ==========")
print("Total records:", len(df))
print("Unique connection IDs:", df["uid"].nunique())

print("\n========== 5. TIMESTAMP RANGE ==========")
print("Earliest timestamp:", df["ts"].min())
print("Latest timestamp:", df["ts"].max())
print(
    "Time difference in seconds:",
    df["ts"].max() - df["ts"].min()
)

print("\n========== 6. LONGEST CONNECTIONS ==========")
print(
    df.nlargest(10, "duration")[
        ["uid", "id.orig_h", "id.resp_h",
         "id.resp_p", "duration", "label"]
    ].to_string(index=False)
)
