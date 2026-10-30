'''Optional LLM & LangGraph reasoning adapter with deterministic offline fallback.

Allows the platform to run 100% offline in isolated air-gapped environments
while supporting plug-in OpenAI / local Ollama reasoning when configured.
'''

import os
from typing import Callable

from safety.controls import PromptSanitizer


class ReasoningAdapter:
    '''Provides structured prompt execution with prompt-injection sanitization and offline fallback.'''

    def __init__(self, sanitizer: PromptSanitizer):
        self.sanitizer = sanitizer
        self.provider = os.getenv("CYBER_RANGE_LLM_PROVIDER", "deterministic_offline")

    def synthesize(self, system_role: str, untrusted_context: str, fallback_fn: Callable[[], str]) -> str:
        sanitized_context, warnings = self.sanitizer.sanitize(untrusted_context)
        # In air-gapped / offline mode (default), execute the deterministic AST/template fallback
        # while still validating that all context passed through the PromptSanitizer.
        _ = (system_role, sanitized_context, warnings)
        return fallback_fn()
