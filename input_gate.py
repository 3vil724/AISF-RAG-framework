import re
import ahocorasick

class InputGate:
    def __init__(self, automaton: ahocorasick.Automaton = None):
        """
        Initializes the InputGate with a pre-compiled Aho-Corasick automaton
        loaded into RAM during the FastAPI lifespan event.
        """
        self.automaton = automaton

    def scan(self, text: str) -> tuple[bool, list[str]]:
        """
        Deterministically scans the input text against all signatures simultaneously.
        Returns a tuple of (is_malicious: bool, matched_signatures: list).
        Complexity: O(N + M) where N is prompt length.
        """
        if not self.automaton:
            return False, []

        matched_signatures = []
        # Single-pass deterministic evaluation over lowercased input text
        for end_index, value in self.automaton.iter(text.lower()):
            matched_signatures.append(value)

        is_malicious = len(matched_signatures) > 0
        return is_malicious, list(set(matched_signatures))

    def sanitize_query(self, text: str) -> str:
        """
        Fallback evaluation interface for legacy sanitization compatibility.
        """
        is_malicious, matches = self.scan(text)
        if is_malicious:
            return "[BLOCKED_INPUT_GATE_VIOLATION]"
        return text
