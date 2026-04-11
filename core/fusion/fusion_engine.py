import os
import numpy as np
import fasttext
import onnxruntime as rt
from loguru import logger


class FusionEngine:

    MAX_LEN   = 50
    THRESHOLD = 0.5

    def __init__(self, config):
        self.config      = config
        self.file_weight = config["fusion"]["file_io_weight"]
        self.net_weight  = config["fusion"]["network_weight"]
        self.thresholds  = config["thresholds"]

        base = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        ))
        onnx_path  = os.path.join(base, "core", "models", "ransomware_detector_v3.onnx")
        embed_path = os.path.join(base, "core", "models", "ransap_embeddings_v3.bin")

        # Load FastText
        logger.info(f"Loading FastText model from {embed_path}")
        self.ft_model  = fasttext.load_model(embed_path)
        self.embed_dim = self.ft_model.get_dimension()
        logger.info(f"FastText loaded | embed_dim={self.embed_dim}")

        # Load ONNX model (88x faster than Keras)
        logger.info(f"Loading ONNX model from {onnx_path}")
        self.session    = rt.InferenceSession(
            onnx_path,
            providers=["CPUExecutionProvider"]
        )
        self.input_name = self.session.get_inputs()[0].name
        logger.info(f"ONNX model loaded | input={self.input_name}")
        logger.info("FusionEngine initialized with ONNX inference")

    def _events_to_tokens(self, events):
        """Convert proto FileEvent objects to RanSAP-style tokens."""
        tokens     = []
        lba_values = []

        for event in events:
            op = event.operation.upper()
            if op not in ["WRITE", "CREATE"]:
                continue

            size = event.bytes
            if size <= 512:
                size_class = "TINY"
            elif size <= 2048:
                size_class = "SMALL"
            else:
                size_class = "LARGE"

            ext = event.file_extension.lower()
            if ext in [".enc", ".locked", ".crypt", ".encrypted"]:
                entropy_class = "ENCRYPTED"
            elif ext in [".jpg", ".mp4", ".zip", ".png"]:
                entropy_class = "HIGH_ENT"
            elif ext in [".docx", ".xlsx", ".pdf"]:
                entropy_class = "MED_ENT"
            elif ext in [".txt", ".log", ".csv"]:
                entropy_class = "LOW_ENT"
            else:
                entropy_class = "NORMAL_ENT"

            lba_values.append(len(lba_values))
            if len(lba_values) > 2:
                diffs  = [abs(lba_values[i+1] - lba_values[i])
                          for i in range(len(lba_values)-1)]
                avg    = sum(diffs) / len(diffs)
                access = "SEQ" if avg < 2 else "RAND"
            else:
                access = "RAND"

            token = f"WRITE_{size_class}_{entropy_class}_{access}"
            tokens.append(token)

        return tokens

    def _vectorize(self, tokens):
        """Convert token list to numpy array. Shape: (1, MAX_LEN, embed_dim)"""
        vecs = []
        for token in tokens[:self.MAX_LEN]:
            vec = self.ft_model.get_word_vector(token)
            vecs.append(np.array(vec, dtype=np.float32))
        while len(vecs) < self.MAX_LEN:
            vecs.append(np.zeros(self.embed_dim, dtype=np.float32))
        arr = np.stack(vecs)
        return arr.reshape(1, self.MAX_LEN, self.embed_dim)

    def _ml_score(self, events):
        """Run ONNX model on events. Returns float 0.0-1.0."""
        try:
            tokens = self._events_to_tokens(events)
            if not tokens:
                return 0.0

            scores = []
            step   = max(1, len(tokens) // 5)

            for i in range(0, max(1, len(tokens) - self.MAX_LEN + 1), step):
                window = tokens[i:i + self.MAX_LEN]
                X      = self._vectorize(window)
                result = self.session.run(None, {self.input_name: X})
                prob   = float(result[0][0][0])
                scores.append(prob)

            return max(scores) if scores else 0.0

        except Exception as e:
            logger.error(f"ML scoring error: {e}")
            return 0.0

    def decide(self, events):
        """Main decision method. Returns (decision, confidence, reason)"""
        ml_score    = self._ml_score(events)
        fused_score = ml_score * self.file_weight

        reason = f"MLScore={ml_score:.3f} FusedScore={fused_score:.3f}"
        logger.debug(f"FusionEngine | {reason}")

        if fused_score >= self.thresholds["critical"]:
            return "ISOLATE", fused_score, reason
        elif fused_score >= self.thresholds["warning"]:
            return "ALERT", fused_score, reason
        else:
            return "LOG", fused_score, reason