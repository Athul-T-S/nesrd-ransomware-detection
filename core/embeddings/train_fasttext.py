import os
import fasttext
from loguru import logger

SEQ_FILE  = r"D:\project\nesrd\nesrd\data\sequences\balanced_sequences_v3.txt"
MODEL_OUT = r"D:\project\nesrd\nesrd\core\models\ransap_embeddings_v3.bin"

def main():
    logger.info("Training FastText on RanSAP sequences...")
    logger.info(f"Input: {SEQ_FILE}")

    # Train FastText unsupervised (skipgram)
    # This learns semantic relationships between tokens
    model = fasttext.train_unsupervised(
        SEQ_FILE,
        model="skipgram",
        dim=50,           # keep same dimension as original model
        epoch=10,
        minCount=5,
        wordNgrams=2,     # capture bigrams like WRITE_LARGE + HIGH_ENTROPY
        thread=4
    )

    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    model.save_model(MODEL_OUT)

    # Verify
    vocab_size = len(model.words)
    logger.info(f"Vocabulary size: {vocab_size}")
    logger.info(f"Embedding dim:   {model.get_dimension()}")
    logger.info(f"Model saved to:  {MODEL_OUT}")

    # Test a few tokens
    test_tokens = [
        "WRITE_LARGE_ENCRYPTED",
        "WRITE_LARGE_NORMAL_ENTROPY",
        "WRITE_LARGE_HIGH_ENTROPY",
        "WRITE_TINY_LOW_ENTROPY"
    ]
    logger.info("\nSample token vectors (first 5 dims):")
    for token in test_tokens:
        vec = model.get_word_vector(token)
        logger.info(f"  {token}: {vec[:5].round(3)}")

if __name__ == "__main__":
    main()