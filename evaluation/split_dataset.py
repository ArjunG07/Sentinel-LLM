import csv
import random
from collections import defaultdict

INPUT_FILE = "evaluation/dataset.csv"
DEV_FILE = "evaluation/dataset_dev.csv"
EVAL_FILE = "evaluation/dataset_eval.csv"

DEV_RATIO = 0.70
SEED = 42


def load_dataset():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def stratified_split(rows):
    random.seed(SEED)

    groups = defaultdict(list)

    # Keep the distribution of attack categories
    # similar in both datasets.
    for row in rows:
        groups[row["category"]].append(row)

    dev_rows = []
    eval_rows = []

    for category, category_rows in groups.items():
        random.shuffle(category_rows)

        dev_count = round(len(category_rows) * DEV_RATIO)

        # Make sure each category represented by multiple cases
        # gets at least one evaluation case.
        if len(category_rows) > 1:
            dev_count = min(dev_count, len(category_rows) - 1)

        dev_rows.extend(category_rows[:dev_count])
        eval_rows.extend(category_rows[dev_count:])

    random.shuffle(dev_rows)
    random.shuffle(eval_rows)

    return dev_rows, eval_rows


def save_dataset(filename, rows):
    if not rows:
        return

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def print_distribution(name, rows):
    counts = defaultdict(int)

    for row in rows:
        counts[row["category"]] += 1

    print(f"\n{name}: {len(rows)} cases")

    for category, count in sorted(counts.items()):
        print(f"  {category}: {count}")


def main():
    rows = load_dataset()

    dev_rows, eval_rows = stratified_split(rows)

    save_dataset(DEV_FILE, dev_rows)
    save_dataset(EVAL_FILE, eval_rows)

    print("=" * 60)
    print("SENTINELLLM DATASET SPLIT")
    print("=" * 60)

    print(f"Original dataset: {len(rows)} cases")
    print_distribution("Development set", dev_rows)
    print_distribution("Evaluation set", eval_rows)

    print("\nFiles created:")
    print(f"  {DEV_FILE}")
    print(f"  {EVAL_FILE}")

    print(f"\nRandom seed: {SEED}")
    print(f"Development ratio: {DEV_RATIO:.0%}")


if __name__ == "__main__":
    main()