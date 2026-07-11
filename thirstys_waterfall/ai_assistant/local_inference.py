"""
Local Inference Engine - On-device AI processing
"""

import logging
from typing import Any, Dict, Optional


class LocalInferenceEngine:
    """
    Local inference engine for on-device AI processing.
    No external API calls, complete privacy.
    """

    def __init__(self, backend: Optional[Any] = None):
        self.logger = logging.getLogger(__name__)
        self.backend = backend
        self.model_loaded = False

    def load_model(self):
        """Load the configured local AI backend."""
        if self.backend is None:
            raise RuntimeError("Local inference backend is not configured")

        self.logger.info("Loading local AI model")
        load_model = getattr(self.backend, "load_model", None)
        if callable(load_model):
            load_model()
        self.model_loaded = True

    def infer(self, input_text: str) -> str:
        """Run inference on-device"""
        if not self.model_loaded:
            self.load_model()

        infer = getattr(self.backend, "infer", None)
        if not callable(infer):
            raise RuntimeError("Local inference backend does not implement infer")

        result = infer(input_text)
        if not isinstance(result, str):
            raise RuntimeError("Local inference backend returned non-text result")
        return result

    def get_status(self) -> Dict[str, Any]:
        """Return evidence-gated backend status."""
        return {
            "model_loaded": self.model_loaded,
            "backend_configured": self.backend is not None,
            "backend_type": type(self.backend).__name__ if self.backend else None,
        }
