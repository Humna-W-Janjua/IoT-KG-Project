
import pandas as pd

# Load the existing sample dataset
df = pd.read_csv("Dataset/iot23_sample.csv")

print("\n========== DATASET OVERVIEW ==========")
print("Shape:", df.shape)

print("\n========== COLUMN INFORMATION ==========")
df.info()

print("\n========== FIRST 5 RECORDS ==========")
print(df.head().to_string())

print("\n========== MISSING VALUES ==========")
print(df.isnull().sum())

print("\n========== DUPLICATE RECORDS ==========")
print("Duplicate rows:", df.duplicated().sum())

print("\n========== THREAT LABEL DISTRIBUTION ==========")
print(df["label"].value_counts(dropna=False))

print("\n========== UNIQUE NETWORK ADDRESSES ==========")
print("Source IPs:", df["id.orig_h"].nunique())
print("Destination IPs:", df["id.resp_h"].nunique())

print("\n========== PROTOCOL DISTRIBUTION ==========")
print(df["proto"].value_counts(dropna=False))

print("\n========== PORT INFORMATION ==========")
print("Unique source ports:", df["id.orig_p"].nunique())
print("Unique destination ports:", df["id.resp_p"].nunique())
print("Most common destination ports:")
print(df["id.resp_p"].value_counts().head(10))

print("\n========== DATA TYPES ==========")
print(df.dtypes)

print("\n========== NUMERIC SUMMARY ==========")
print(df.describe())
