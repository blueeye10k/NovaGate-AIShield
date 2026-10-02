import math
import re
from typing import Tuple, Dict, List

class VectorThreatEvaluator:
    """
    Mathematical Heuristic Inspection Engine combining structural Shannon Entropy,
    Vector Profile Distances, and multi-variable heuristic pattern tracking.
    """
    JAILBREAK_ANCHORS = ["ignore all prior", "system developer mode", "bypass restrictions", "unrestricted mode", "reveal system prompt", "dump configuration records"]

    HEURISTIC_MATRICES = {
        "INSTRUCTION_BIAS_OVERRIDE": {
            "signatures": [r"ignore\s+instructions", r"forget\s+rules", r"override\s+policy", r"stop\s+filtering"],
            "base_criticality": 4.8
        },
        "ROLEPLAY_COMPROMISE": {
            "signatures": [r"act\s+as\s+a", r"pretend\s+to\s+be", r"you\s+are\s+now\s+a", r"hypothetical\s+simulation"],
            "base_criticality": 3.6
        },
        "ASSET_EXFILTRATION": {
            "signatures": [r"reveal\s+system\s+prompt", r"dump\s+configuration", r"output\s+initial\s+text", r"show\s+hidden\s+rules"],
            "base_criticality": 5.0
        }
    }

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        char_frequencies = {}
        for char in text:
            char_frequencies[char] = char_frequencies.get(char, 0) + 1
        
        entropy = 0.0
        for occurrences in char_frequencies.values():
            probability = occurrences / len(text)
            entropy -= probability * math.log2(probability)
        return round(entropy, 3)

    @classmethod
    def calculate_semantic_vector_distance(cls, text: str) -> float:
        words = text.lower().split()
        if not words:
            return 0.0
        
        match_vector_hits = 0
        for anchor in cls.JAILBREAK_ANCHORS:
            anchor_words = anchor.split()
            if any(aw in words for aw in anchor_words):
                match_vector_hits += 1
                
        return round((match_vector_hits / len(cls.JAILBREAK_ANCHORS)) * 10.0, 2)

    @classmethod
    def evaluate_threat_vector(cls, processed_string: str) -> Tuple[bool, dict]:
        calculated_risk_index = 0.0
        signatures_triggered = []

        # 1. Structural Pattern Parsing Loop
        for category, matrix in cls.HEURISTIC_MATRICES.items():
            trigger_density = 0
            for signature in matrix["signatures"]:
                if re.search(signature, processed_string):
                    trigger_density += 1
            if trigger_density > 0:
                weighted_score = matrix["base_criticality"] * (1 + (trigger_density - 1) * 0.4)
                calculated_risk_index += weighted_score
                signatures_triggered.append(category)

        # 2. Vector Metric Aggregation
        vector_proximity = cls.calculate_semantic_vector_distance(processed_string)
        calculated_risk_index += (vector_proximity * 0.8)
        if vector_proximity > 2.0:
            signatures_triggered.append("SEMANTIC_VECTOR_ANOMALY")

        # 3. Entropy Metric Analysis
        entropy_score = cls.calculate_shannon_entropy(processed_string)
        if entropy_score > 5.0:
            calculated_risk_index += 0.8
            signatures_triggered.append("HIGH_STRUCTURAL_COMPLEXITY")

        verdict_state = calculated_risk_index >= 5.5

        return verdict_state, {
            "calculated_risk_index": round(min(calculated_risk_index, 10.0), 2),
            "signatures_triggered": signatures_triggered,
            "entropy_score": entropy_score,
            "vector_proximity": vector_proximity,
            "verdict": "REJECT" if verdict_state else "PASS"
        }
