import os
import numpy as np
import fasttext
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, GlobalMaxPooling1D, Dense, Dropout, Input
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from loguru import logger

SEQ_FILE   = r"D:\project\nesrd\nesrd\data\sequences\balanced_sequences_v3.txt"
LABEL_FILE = r"D:\project\nesrd\nesrd\data\sequences\balanced_labels_v3.txt"
EMBED_FILE = r"D:\project\nesrd\nesrd\core\models\ransap_embeddings_v3.bin"
MODEL_OUT  = r"D:\project\nesrd\nesrd\core\models\ransomware_detector_ransap_v3.h5"
MAX_LEN    = 50   # must match FastText training window size


def load_data():
    logger.info("Loading sequences and labels...")
    with open(SEQ_FILE, "r") as f:
        sequences = [line.strip().split() for line in f if line.strip()]
    with open(LABEL_FILE, "r") as f:
        labels = [int(line.strip()) for line in f if line.strip()]
    logger.info(f"Loaded {len(sequences)} sequences")
    return sequences, labels


def vectorize(sequences, ft_model):
    logger.info("Vectorizing sequences...")
    embed_dim = ft_model.get_dimension()
    X = []
    for seq in sequences:
        vecs = []
        for token in seq[:MAX_LEN]:
            vec = ft_model.get_word_vector(token)
            vecs.append(np.array(vec, dtype=np.float32))
        while len(vecs) < MAX_LEN:
            vecs.append(np.zeros(embed_dim, dtype=np.float32))
        X.append(np.stack(vecs))
    X = np.stack(X)
    logger.info(f"X shape: {X.shape}")
    return X, embed_dim


def build_model(embed_dim):
    model = Sequential([
        Input(shape=(MAX_LEN, embed_dim)),
        Conv1D(128, 3, activation="relu", padding="same"),
        Conv1D(64, 3, activation="relu", padding="same"),
        GlobalMaxPooling1D(),
        Dense(64, activation="relu"),
        Dropout(0.3),
        Dense(32, activation="relu"),
        Dense(1, activation="sigmoid")
    ])
    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy",
                 tf.keras.metrics.Precision(name="precision"),
                 tf.keras.metrics.Recall(name="recall")]
    )
    model.summary()
    return model


def main():
    # Load FastText
    logger.info("Loading FastText model...")
    ft_model = fasttext.load_model(EMBED_FILE)

    # Load and vectorize data
    sequences, labels = load_data()
    X, embed_dim      = vectorize(sequences, ft_model)
    y = np.array(labels, dtype=np.float32)

    # Train/val/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.1, random_state=42, stratify=y_train
    )

    logger.info(f"Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}")

    # Build model
    model = build_model(embed_dim)

    # Callbacks
    callbacks = [
        EarlyStopping(patience=3, restore_best_weights=True,
                      monitor="val_accuracy"),
        ModelCheckpoint(MODEL_OUT, save_best_only=True,
                        monitor="val_accuracy", verbose=1)
    ]

    # Train
    logger.info("Training Conv1D model...")
    history = model.fit(
        X_train, y_train,
        epochs          = 15,
        batch_size      = 512,
        validation_data = (X_val, y_val),
        callbacks       = callbacks,
        verbose         = 1
    )

    # Evaluate on test set
    logger.info("\nEvaluating on test set...")
    loss, acc, precision, recall = model.evaluate(X_test, y_test, verbose=0)
    f1 = 2 * (precision * recall) / (precision + recall + 1e-8)

    logger.info(f"\n{'='*50}")
    logger.info(f"Test Accuracy:  {acc:.4f}")
    logger.info(f"Test Precision: {precision:.4f}")
    logger.info(f"Test Recall:    {recall:.4f}")
    logger.info(f"Test F1 Score:  {f1:.4f}")

    # Confusion matrix
    y_pred = (model.predict(X_test, verbose=0) > 0.5).astype(int).flatten()
    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"\nConfusion Matrix:")
    logger.info(f"  TN={cm[0][0]} FP={cm[0][1]}")
    logger.info(f"  FN={cm[1][0]} TP={cm[1][1]}")

    fpr = cm[0][1] / (cm[0][1] + cm[0][0] + 1e-8)
    logger.info(f"\nFalse Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
    logger.info(f"Model saved to: {MODEL_OUT}")


if __name__ == "__main__":
    main()
    