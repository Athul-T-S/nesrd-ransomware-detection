import os
import pandas as pd
import numpy as np

BASE_PATH = r"D:\project\nesrd\nesrd\data\raw\ransap\RanSAP\dataset\original\win7-120gb-ssd"

RANSOMWARE = ["Ryuk", "WannaCry", "Sodinokibi", "GandCrab4"]
BENIGN     = ["Excel", "Firefox"]

def explore_folder(family, label):
    family_path = os.path.join(BASE_PATH, family)
    runs        = os.listdir(family_path)
    print(f"\n{'='*60}")
    print(f"Family: {family} | Label: {label} | Runs: {len(runs)}")

    # Look at first run
    first_run = os.path.join(family_path, runs[0])
    write_csv = os.path.join(first_run, "ata_write.csv")

    if not os.path.exists(write_csv):
        print(f"  No ata_write.csv found in {first_run}")
        return

    df = pd.read_csv(write_csv, header=None,
                     names=["timestamp", "elapsed_time", "lba",
                            "size", "entropy_before", "entropy_after"])

    print(f"  Rows: {len(df)}")
    print(f"  Size range: {df['size'].min()} - {df['size'].max()}")
    print(f"  Entropy_after range: {df['entropy_after'].min():.3f} - {df['entropy_after'].max():.3f}")
    print(f"  Sample rows:")
    print(df.head(3).to_string())

if __name__ == "__main__":
    for family in RANSOMWARE:
        explore_folder(family, 1)
    for family in BENIGN:
        explore_folder(family, 0)