"""
Guardrails module for securing RAG pipeline.
"""
from .input_guard import InputGuard, InputCheckResult
from .document_sanitizer import DocumentSanitizer
from .system_prompt import SystemPromptManager
from .trust_scorer import TrustScorer
from .output_guard import OutputGuard, OutputCheckResult
from .logger import SecurityLogger
from .semantic_guard import SemanticGuard, SemanticCheckResult
from .llm_judge import LLMJudge, JudgeResult
from .canary import CanaryGuard, CanaryResult
from .threat_engine import ThreatEngine, FusionResult, LayerTrace

__all__ = [
    "InputGuard",
    "InputCheckResult",
    "DocumentSanitizer",
    "SystemPromptManager",
    "TrustScorer",
    "OutputGuard",
    "OutputCheckResult",
    "SecurityLogger",
    "SemanticGuard",
    "SemanticCheckResult",
    "LLMJudge",
    "JudgeResult",
    "CanaryGuard",
    "CanaryResult",
    "ThreatEngine",
    "FusionResult",
    "LayerTrace",
    "GuardrailsManager",
]


class GuardrailsManager:
    """
    Convenience container that wires together every guardrail component into a
    coherent, multi-layer defence.

    Layers:
      * input_guard    — fast regex/signature screening
      * semantic_guard — embedding-similarity screening (reuses embedding model)
      * llm_judge      — optional LLM-as-judge escalation for ambiguous inputs
      * threat_engine  — fuses the three input layers into one explainable verdict
      * doc_sanitizer  — strips embedded instructions from retrieved chunks
      * prompt_manager — locked, non-overridable system prompt
      * trust_scorer   — retrieval-weighted content trust + context limiting
      * canary         — system-prompt-leak detection
      * output_guard   — PII redaction + harmful-content blocking
      * logger         — persistent, thread-safe security audit trail
    """

    def __init__(self, embedding_model=None, llm=None):
        self.input_guard = InputGuard()
        self.doc_sanitizer = DocumentSanitizer()
        self.prompt_manager = SystemPromptManager()
        self.trust_scorer = TrustScorer()
        self.output_guard = OutputGuard()
        self.logger = SecurityLogger()

        # Advanced (v2) layers.
        self.semantic_guard = SemanticGuard(embedding_model=embedding_model)
        self.llm_judge = LLMJudge(llm=llm)
        self.canary = CanaryGuard()
        self.threat_engine = ThreatEngine(
            input_guard=self.input_guard,
            semantic_guard=self.semantic_guard,
            llm_judge=self.llm_judge,
        )
