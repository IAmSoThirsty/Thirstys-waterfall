"""Optional Project-AI / enhanced Thirsty-Lang binding.

The public package must be able to import and run without undeclared local
modules. When the enhanced Thirsty-Lang `utf.tarl` package is present, this
module delegates to it. When it is not present, callers get an explicit
unavailable status instead of a fake governance claim or an import-time crash.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
import os
import sys
import logging


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SovereignBindingStatus:
    available: bool
    module: str = "unavailable"
    backend: str = "none"
    reason: Optional[str] = None
    source_path: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "available": self.available,
            "module": self.module,
            "backend": self.backend,
            "reason": self.reason,
            "source_path": self.source_path,
        }


def _configure_thirsty_lang_path() -> Optional[str]:
    for name in ("THIRSTY_LANG_PATH", "THIRSTY_LANG_REPO"):
        raw_path = os.getenv(name)
        if not raw_path:
            continue

        root = Path(raw_path).expanduser()
        src = root / "src"
        import_path = src if src.exists() else root
        if import_path.exists():
            path_text = str(import_path)
            if path_text not in sys.path:
                sys.path.insert(0, path_text)
            return str(root)
    return None


_SOURCE_PATH = _configure_thirsty_lang_path()

try:
    from utf.tarl import TarlRuntime, TarlVerdict  # type: ignore

    _BINDING_STATUS = SovereignBindingStatus(
        available=True,
        module="utf.tarl",
        backend="thirsty-lang",
        source_path=_SOURCE_PATH,
    )
except ImportError as exc:
    TarlRuntime = None
    TarlVerdict = None
    _BINDING_STATUS = SovereignBindingStatus(
        available=False,
        reason=str(exc),
        source_path=_SOURCE_PATH,
    )


def get_sovereign_binding_status() -> SovereignBindingStatus:
    """Return whether the optional external governance binding is available."""
    return _BINDING_STATUS


def execute_sovereign_protocol(context: Any, target_protocol: str) -> Optional[Any]:
    """Run the external protocol when available; otherwise report unavailability."""
    if not _BINDING_STATUS.available:
        logger.warning(
            "Optional %s binding unavailable; skipping protocol %s: %s",
            _BINDING_STATUS.module,
            target_protocol,
            _BINDING_STATUS.reason,
        )
        return None

    policy_text = os.getenv(
        "THIRSTY_WATERFALL_INIT_POLICY",
        'policy waterfall_init:\n  when protocol == "INIT_PROTOCOL" => ALLOW',
    )
    runtime = TarlRuntime()
    try:
        decision, proof = runtime.evaluate_with_proof(
            {
                "protocol": target_protocol,
                "action": target_protocol,
                "component": "thirstys-waterfall",
            },
            policy_text=policy_text,
        )
        if decision.verdict != TarlVerdict.ALLOW:
            raise PermissionError(
                "Sovereign protocol denied: {0}".format(decision.reason)
            )
        return {
            "backend": _BINDING_STATUS.backend,
            "verdict": str(decision.verdict),
            "reason": decision.reason,
            "proof": proof.to_dict(),
        }
    finally:
        runtime.shutdown()
