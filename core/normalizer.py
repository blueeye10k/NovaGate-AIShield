import base64
import binascii
import urllib.parse
import re

class AdvancedPayloadNormalizer:
    """
    Production-grade payload scrubbing engine that unwraps multi-layered obfuscations recursively.
    """
    LEET_DICT = {'4': 'a', '3': 'e', '1': 'i', '0': 'o', '7': 't', '5': 's', '8': 'b', '@': 'a', '$': 's'}

    @classmethod
    def strip_leet(cls, text: str) -> str:
        return "".join([cls.LEET_DICT.get(char, char) for char in text.lower()])

    @classmethod
    def extract_hex(cls, text: str) -> str:
        cleaned = re.sub(r'[\s\\x:]', '', text)
        if len(cleaned) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', cleaned):
            try:
                return bytes.fromhex(cleaned).decode('utf-8', errors='ignore')
            except ValueError:
                pass
        return text

    @classmethod
    def extract_b64(cls, text: str) -> str:
        cleaned = re.sub(r'[\s\n\r]', '', text)
        if len(cleaned) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', cleaned):
            try:
                return base64.b64decode(cleaned, validate=True).decode('utf-8', errors='ignore')
            except (binascii.Error, ValueError):
                pass
        return text

    @classmethod
    def execute_normalization_pipeline(cls, raw_input: str) -> dict:
        current_payload = raw_input
        layers_unwrapped = []

        for iteration in range(4):
            previous_payload = current_payload

            # Check URL Encoding
            url_decoded = urllib.parse.unquote(current_payload)
            if url_decoded != current_payload:
                layers_unwrapped.append(f"Pass_{iteration}_URL_Decode")
                current_payload = url_decoded

            # Check Base64 Obfuscation
            b64_decoded = cls.extract_b64(current_payload)
            if b64_decoded != current_payload:
                layers_unwrapped.append(f"Pass_{iteration}_Base64_Stripper")
                current_payload = b64_decoded

            # Check Hex Obfuscation
            hex_decoded = cls.extract_hex(current_payload)
            if hex_decoded != current_payload:
                layers_unwrapped.append(f"Pass_{iteration}_Hex_Decoder")
                current_payload = hex_decoded

            if current_payload == previous_payload:
                break

        # Strip Leetspeak encoding anomalies
        standardized_payload = cls.strip_leet(current_payload)
        if standardized_payload != current_payload:
            layers_unwrapped.append("LeetSpeak_Normalization")
            current_payload = standardized_payload

        return {
            "processed_string": current_payload.lower().strip(),
            "pipeline_telemetry": list(set(layers_unwrapped))
        }
