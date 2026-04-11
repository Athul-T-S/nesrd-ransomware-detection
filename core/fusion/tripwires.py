from loguru import logger


class TripwireEngine:

    def __init__(self, config):
        self.config    = config["tripwires"]
        self.rename_counts = {}
        logger.info("TripwireEngine initialized")

    def check(self, events):
        """
        Hard deterministic rules - fire immediately, no ML.
        Returns {"triggered": bool, "reason": str}
        """
        rename_count = 0

        for event in events:
            file_lower = event.file_path.lower()
            op         = event.operation.upper()

            # VSS deletion - ransomware kills shadow copies
            if "vssadmin" in file_lower and "delete" in file_lower:
                return {"triggered": True, "reason": "VSS shadow copy deletion detected"}

            # Boot recovery disable
            if "bcdedit" in file_lower:
                return {"triggered": True, "reason": "Boot recovery modification detected"}

            # Ransom note filenames
            for pattern in self.config["ransom_note_patterns"]:
                if pattern.lower() in file_lower:
                    return {"triggered": True, "reason": f"Ransom note detected: {pattern}"}

            # Count renames
            if op == "RENAME":
                rename_count += 1

        # Rapid rename check
        threshold = self.config["rapid_rename_threshold"]
        if rename_count >= threshold:
            return {
                "triggered": True,
                "reason": f"Rapid rename: {rename_count} files renamed in one window"
            }

        return {"triggered": False, "reason": ""}