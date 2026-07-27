import re
import base64


class InputGate:
    def __init__(self):
        self.danger_keywords = ["ignore", "override", "drop table", "hacker", "system prompt"]

    def sanitize_query(self, user_prompt):
        lower_prompt = user_prompt.lower()

        for keyword in self.danger_keywords:
            if keyword in lower_prompt:
                return "[SECURITY GATE: Malicious intent detected and neutralized.]"

        # FIXED REGEX: Now requires at least 40 continuous characters to trigger the Base64 warning.
        # This prevents normal English words (like "summarize") from getting flagged.
        if re.search(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', user_prompt):
            return "[SECURITY GATE: Obfuscated data payload detected and neutralized.]"

        special_char_count = len(re.findall(r'[^a-zA-Z0-9\s]', user_prompt))

        if len(user_prompt) > 10 and (special_char_count / len(user_prompt)) > 0.15:
            return "[SECURITY GATE: Malformed syntax payload detected and neutralized.]"

        return user_prompt
