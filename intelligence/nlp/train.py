"""
train.py

Simple training script placeholder for PHISHGUARD NLP.
"""
import argparse
from intelligence.nlp.dataset import Dataset
from intelligence.nlp.model import Model


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/", help="Path to training data")
    parser.add_argument("--model-out", default="models/model.json", help="Output model path")
    args = parser.parse_args()

    ds = Dataset(args.data)
    examples = ds.load()

    model = Model()
    model.build()
    model.train(examples)
    model.save(args.model_out)
    print(f"Saved model to {args.model_out}")


if __name__ == "__main__":
    main()
