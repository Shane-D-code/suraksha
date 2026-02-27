import pandas as pd

DATA_PATH = "data/raw/emails/phishing_email.csv"

def load_email_dataset():
    df = pd.read_csv(DATA_PATH)
    return df

if __name__ == "__main__":
    data = load_email_dataset()
    print(data.head())
    print("\nColumns:", list(data.columns))
    print("Total samples:", len(data))