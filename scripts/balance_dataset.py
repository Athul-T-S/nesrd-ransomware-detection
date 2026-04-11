import random
from loguru import logger

SEQ_FILE      = r"D:\project\nesrd\nesrd\data\sequences\ransap_sequences_v3.txt"
LABEL_FILE    = r"D:\project\nesrd\nesrd\data\sequences\ransap_labels_v3.txt"
OUT_SEQ_FILE  = r"D:\project\nesrd\nesrd\data\sequences\balanced_sequences_v3.txt"
OUT_LAB_FILE  = r"D:\project\nesrd\nesrd\data\sequences\balanced_labels_v3.txt"
MAX_PER_CLASS = 89000  # cap both classes at this number
SEED          = 42

def main():
    random.seed(SEED)

    logger.info("Loading sequences...")
    with open(SEQ_FILE, "r") as f:
        sequences = f.read().splitlines()
    with open(LABEL_FILE, "r") as f:
        labels = f.read().splitlines()

    logger.info(f"Total loaded: {len(sequences)}")

    # Separate by class
    ransomware = [(s, l) for s, l in zip(sequences, labels) if l == "1"]
    benign     = [(s, l) for s, l in zip(sequences, labels) if l == "0"]

    logger.info(f"Ransomware: {len(ransomware)}")
    logger.info(f"Benign:     {len(benign)}")

    # Downsample ransomware
    random.shuffle(ransomware)
    random.shuffle(benign)
    ransomware = ransomware[:MAX_PER_CLASS]
    benign     = benign[:MAX_PER_CLASS]

    # Combine and shuffle
    combined = ransomware + benign
    random.shuffle(combined)

    final_seqs   = [s for s, l in combined]
    final_labels = [l for s, l in combined]

    # Save
    with open(OUT_SEQ_FILE, "w") as f:
        f.write("\n".join(final_seqs))
    with open(OUT_LAB_FILE, "w") as f:
        f.write("\n".join(final_labels))

    ransomware_count = final_labels.count("1")
    benign_count     = final_labels.count("0")

    logger.info(f"\nBalanced dataset:")
    logger.info(f"  Ransomware: {ransomware_count}")
    logger.info(f"  Benign:     {benign_count}")
    logger.info(f"  Total:      {len(final_seqs)}")
    logger.info(f"  Saved to:   {OUT_SEQ_FILE}")

if __name__ == "__main__":
    main()