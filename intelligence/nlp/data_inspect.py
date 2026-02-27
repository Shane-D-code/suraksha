import pandas as pd

df = pd.read_csv("data/raw/emails/phishing_email.csv")

print("Label distribution:")
print(df["label"].value_counts())
print("\nLabel percentages:")
print(df["label"].value_counts(normalize=True) * 100)