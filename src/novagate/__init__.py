"""NovaGate-AIShield: a transparent, dependency-light AI prompt firewall.

Public API:

    from novagate import AdvancedPayloadNormalizer, VectorThreatEvaluator

Both are pure, side-effect free and importable without the web layer, so the
detection logic can be embedded in a service, a CLI or a test suite without
pulling in FastAPI.
"""

from novagate.config import Settings, settings
from novagate.evaluator import VectorThreatEvaluator
from novagate.normalizer import AdvancedPayloadNormalizer, NormalizationReport, normalize
from novagate.signatures import CATEGORIES, DetectionCategory

__all__ = [
    "AdvancedPayloadNormalizer",
    "CATEGORIES",
    "DetectionCategory",
    "NormalizationReport",
    "VectorThreatEvaluator",
    "normalize",
    "Settings",
    "settings",
]

__version__ = "3.0.0"
