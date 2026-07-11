"""Tests for local inference backend gating."""

import unittest

from thirstys_waterfall.ai_assistant import LocalInferenceEngine


class FakeLocalBackend:
    """Small deterministic local backend used to verify delegation."""

    def __init__(self):
        self.loaded = False
        self.inputs = []

    def load_model(self):
        self.loaded = True

    def infer(self, input_text: str) -> str:
        self.inputs.append(input_text)
        return f"backend response: {input_text}"


class NonTextBackend:
    def infer(self, input_text: str):
        return {"response": input_text}


class TestLocalInferenceEngine(unittest.TestCase):
    def test_without_backend_fails_closed(self):
        engine = LocalInferenceEngine()

        self.assertFalse(engine.get_status()["backend_configured"])
        with self.assertRaisesRegex(
            RuntimeError, "Local inference backend is not configured"
        ):
            engine.infer("hello")
        self.assertFalse(engine.model_loaded)

    def test_delegates_to_configured_backend(self):
        backend = FakeLocalBackend()
        engine = LocalInferenceEngine(backend=backend)

        result = engine.infer("hello")

        self.assertEqual(result, "backend response: hello")
        self.assertTrue(backend.loaded)
        self.assertTrue(engine.model_loaded)
        self.assertEqual(backend.inputs, ["hello"])
        self.assertEqual(
            engine.get_status(),
            {
                "model_loaded": True,
                "backend_configured": True,
                "backend_type": "FakeLocalBackend",
            },
        )

    def test_backend_must_return_text(self):
        engine = LocalInferenceEngine(backend=NonTextBackend())

        with self.assertRaisesRegex(RuntimeError, "returned non-text result"):
            engine.infer("hello")


if __name__ == "__main__":
    unittest.main()
