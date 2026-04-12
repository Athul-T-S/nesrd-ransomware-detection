import os
from datetime import datetime
from loguru import logger


class BehaviorTokenizer:
    """
    Converts raw FileEvent objects into behavioral tokens.
    
    Token format: OPERATION_EXTENSION_SIZECLASS_SPEED
    Example:      WRITE_DOCX_LARGE_BURST
    """

    # Size thresholds
    SMALL  = 4 * 1024          # < 4KB
    MEDIUM = 512 * 1024        # < 512KB
    LARGE  = 512 * 1024        # >= 512KB

    # Speed tracking window (seconds)
    SPEED_WINDOW_SEC = 5
    BURST_THRESHOLD  = 10      # 10+ ops in 5 seconds = BURST
    RAPID_THRESHOLD  = 50      # 50+ ops in 5 seconds = RAPID

    def __init__(self):
        self._op_timestamps = []  # track recent op times for speed
        logger.info("BehaviorTokenizer initialized")

    def _get_size_class(self, bytes_count):
        """Classify file operation size."""
        if bytes_count < self.SMALL:
            return "SMALL"
        elif bytes_count < self.LARGE:
            return "MEDIUM"
        else:
            return "LARGE"

    def _get_speed_class(self):
        """
        Classify operation speed based on recent history.
        Looks at how many ops occurred in last 5 seconds.
        """
        now = datetime.now().timestamp()

        # Keep only recent timestamps
        self._op_timestamps = [
            t for t in self._op_timestamps
            if now - t <= self.SPEED_WINDOW_SEC
        ]
        self._op_timestamps.append(now)

        count = len(self._op_timestamps)

        if count >= self.RAPID_THRESHOLD:
            return "RAPID"
        elif count >= self.BURST_THRESHOLD:
            return "BURST"
        else:
            return "SINGLE"

    def _normalize_extension(self, ext):
        """
        Convert file extension to token-friendly format.
        .docx -> DOCX
        .unknown_ext -> UNKNOWN
        """
        if not ext:
            return "NOEXT"

        known_extensions = {
            ".docx", ".xlsx", ".pdf", ".jpg", ".png",
            ".db",   ".sql",  ".bak", ".zip", ".pptx",
            ".txt",  ".csv",  ".exe", ".dll", ".enc",
            ".locked", ".crypt"
        }

        if ext.lower() in known_extensions:
            return ext.upper().replace(".", "")
        else:
            # Unknown extension - suspicious if files are being
            # renamed TO unknown extensions (ransomware behavior)
            return "UNKNOWN"

    def _detect_ext_change(self, file_path):
        """
        Detect if a rename operation changes the file extension.
        e.g. document.docx -> document.docx.locked
        This is one of the strongest ransomware signals.
        """
        path_lower = file_path.lower()
        ransomware_exts = [
            ".locked", ".enc", ".encrypted", ".crypt",
            ".crypto", ".xxx", ".zepto", ".cerber"
        ]
        for ext in ransomware_exts:
            if path_lower.endswith(ext):
                return True
        return False

    def tokenize(self, event):
        """
        Convert a single FileEvent into a behavioral token string.
        
        Examples:
            WRITE_DOCX_LARGE_BURST
            RENAME_PDF_EXT_CHANGE        <- very suspicious
            DELETE_XLSX_SMALL_RAPID      <- very suspicious
            CREATE_UNKNOWN_LARGE_SINGLE
        """
        operation  = event.operation.upper()
        ext_token  = self._normalize_extension(event.file_extension)
        size_class = self._get_size_class(event.bytes)
        speed      = self._get_speed_class()

        # Special case - rename to ransomware extension
        if operation == "RENAME" and self._detect_ext_change(event.file_path):
            token = f"RENAME_{ext_token}_EXT_CHANGE"
            logger.warning(f"Suspicious rename detected: {event.file_path}")
            return token

        token = f"{operation}_{ext_token}_{size_class}_{speed}"
        return token

    def tokenize_window(self, events):
        """
        Convert a list of FileEvents into a sequence of tokens.
        This sequence is what gets fed into FastText + Conv1D.
        
        Returns a list of token strings.
        """
        tokens = []
        for event in events:
            token = self.tokenize(event)
            tokens.append(token)

        logger.debug(f"Tokenized {len(events)} events into {len(tokens)} tokens")
        return tokens

    def tokens_to_sentence(self, tokens):
        """
        Convert token list to a space-separated string.
        This is the format FastText expects.
        
        Example: "WRITE_DOCX_LARGE_BURST RENAME_PDF_EXT_CHANGE DELETE_XLSX_SMALL_RAPID"
        """
        return " ".join(tokens)