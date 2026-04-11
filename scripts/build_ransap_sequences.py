import os
import pandas as pd
import numpy as np
from loguru import logger

BASE_PATH  = r"D:\project\nesrd\nesrd\data\raw\ransap\RanSAP\dataset\original\win7-120gb-ssd"
OUTPUT_DIR = r"D:\project\nesrd\nesrd\data\sequences"
SEQ_FILE   = os.path.join(OUTPUT_DIR, "ransap_sequences_v3.txt")
LABEL_FILE = os.path.join(OUTPUT_DIR, "ransap_labels_v3.txt")
RANSOMWARE  = ["Ryuk", "WannaCry", "Sodinokibi", "GandCrab4"]
BENIGN      = ["Excel", "Firefox"]
WINDOW_SIZE = 50
STEP_SIZE   = 10


def get_size_class(size):
    if size <= 512:
        return "TINY"
    elif size <= 2048:
        return "SMALL"
    else:
        return "LARGE"


def get_entropy_class(entropy_after, entropy_before):
    delta = entropy_after - entropy_before
    if entropy_after > 0.85:
        return "ENCRYPTED"
    elif entropy_after > 0.70:
        return "HIGH_ENT"
    elif entropy_after > 0.50:
        return "MED_ENT"
    elif delta > 0.15:
        return "ENT_RISING"
    elif delta < -0.15:
        return "ENT_FALLING"
    elif entropy_after < 0.10:
        return "LOW_ENT"
    else:
        return "NORMAL_ENT"


def get_lba_pattern(lba_series):
    """
    Detect sequential vs random disk access.
    Ransomware often does sequential writes across many files.
    """
    if len(lba_series) < 2:
        return "SEQ"
    diffs = np.abs(np.diff(lba_series))
    avg_diff = np.mean(diffs)
    if avg_diff < 100:
        return "SEQ"       # sequential access
    elif avg_diff < 10000:
        return "NEAR"      # nearby sectors
    else:
        return "RAND"      # random access


def process_run(run_path, family, label):
    write_csv = os.path.join(run_path, "ata_write.csv")
    if not os.path.exists(write_csv):
        return [], []

    df = pd.read_csv(
        write_csv, header=None,
        names=["timestamp", "elapsed_time", "lba",
               "size", "entropy_before", "entropy_after"]
    )

    if len(df) < WINDOW_SIZE:
        return [], []

    sequences = []
    labels    = []

    for i in range(0, len(df) - WINDOW_SIZE + 1, STEP_SIZE):
        window = df.iloc[i:i + WINDOW_SIZE]

        # Get LBA pattern for this window
        lba_pattern = get_lba_pattern(window["lba"].values)

        # Tokenize each row with richer features
        tokens = []
        for _, row in window.iterrows():
            size_class    = get_size_class(row["size"])
            entropy_class = get_entropy_class(
                row["entropy_after"], row["entropy_before"]
            )
            token = f"WRITE_{size_class}_{entropy_class}_{lba_pattern}"
            tokens.append(token)

        sequences.append(" ".join(tokens))
        labels.append(str(label))

    return sequences, labels


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_sequences = []
    all_labels    = []

    for family, label in [(f, 1) for f in RANSOMWARE] + \
                         [(f, 0) for f in BENIGN]:

        family_path = os.path.join(BASE_PATH, family)
        runs        = sorted(os.listdir(family_path))
        fam_seqs    = 0

        for run in runs:
            run_path = os.path.join(family_path, run)
            if not os.path.isdir(run_path):
                continue
            seqs, labs = process_run(run_path, family, label)
            all_sequences.extend(seqs)
            all_labels.extend(labs)
            fam_seqs += len(seqs)

        logger.info(f"{family} (label={label}): {fam_seqs} sequences")

    # Save unbalanced first
    with open(SEQ_FILE, "w") as f:
        f.write("\n".join(all_sequences))
    with open(LABEL_FILE, "w") as f:
        f.write("\n".join(all_labels))

    ransomware_count = all_labels.count("1")
    benign_count     = all_labels.count("0")

    logger.info(f"\nTotal:      {len(all_sequences)}")
    logger.info(f"Ransomware: {ransomware_count}")
    logger.info(f"Benign:     {benign_count}")

    # Show vocabulary
    vocab = set()
    for seq in all_sequences[:10000]:
        for token in seq.split():
            vocab.add(token)
    logger.info(f"Vocabulary size: {len(vocab)}")
    logger.info(f"Tokens: {sorted(vocab)}")

    # Sample sequences
    logger.info(f"\nSample ransomware: {all_sequences[0]}")
    benign_idx = next(i for i, l in enumerate(all_labels) if l == "0")
    logger.info(f"Sample benign:     {all_sequences[benign_idx]}")


if __name__ == "__main__":
    main()