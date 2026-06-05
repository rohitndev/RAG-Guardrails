"""
Threat-fusion engine — combines the independent input-guard layers (regex,
semantic similarity, and an optional LLM judge) into a single, explainable
decision.

Each layer votes with a 0..1 risk score. Rather than naively averaging, the
engine takes the strongest signal and lets weaker corroborating signals nudge it
upward (diminishing returns), which mirrors how a human analyst escalates: one
high-confidence detector is enough, but multiple medium signals together are
also meaningful. Every layer's contribution is recorded so the UI can render an
explainable trace.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LayerTrace:
    """One layer's contribution to the fused decision."""
    name: str
    status: str          # "pass" | "warn" | "block" | "skipped"
    score: float
    detail: str = ""
    category: str = ""


@dataclass
class FusionResult:
    """Aggregated, explainable input-screening decision."""
    blocked: bool
    decision: str                       # "allow" | "warn" | "block"
    threat_level: float                 # fused 0..1 score
    reason: str = ""
    primary_category: str = ""
    layers: List[LayerTrace] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


_REASON_MAP = {
    "instruction_override": "Attempt to override system instructions detected",
    "roleplay": "Role-play / persona-hijack manipulation detected",
    "jailbreak": "Jailbreak attempt detected",
    "prompt_injection": "Prompt injection attempt detected",
    "data_extraction": "System-prompt / data extraction attempt detected",
    "sensitive_exfiltration": "Sensitive-data exfiltration attempt detected",
    "output_control": "Output manipulation attempt detected",
    "markup_injection": "Markup-based injection detected",
    "code_block_injection": "Code-block injection detected",
    "markdown_injection": "Markdown-based injection detected",
}


class ThreatEngine:
    """Fuse the input-screening layers into one explainable verdict."""

    def __init__(
        self,
        input_guard=None,
        semantic_guard=None,
        llm_judge=None,
        block_threshold: Optional[float] = None,
        warn_threshold: Optional[float] = None,
        llm_judge_enabled: Optional[bool] = None,
        gray_low: Optional[float] = None,
        gray_high: Optional[float] = None,
    ):
        self.input_guard = input_guard
        self.semantic_guard = semantic_guard
        self.llm_judge = llm_judge

        try:
            from config import (
                FUSION_BLOCK_THRESHOLD, FUSION_WARN_THRESHOLD,
                LLM_JUDGE_ENABLED, LLM_JUDGE_GRAY_LOW, LLM_JUDGE_GRAY_HIGH,
            )
        except Exception:
            FUSION_BLOCK_THRESHOLD, FUSION_WARN_THRESHOLD = 0.75, 0.45
            LLM_JUDGE_ENABLED, LLM_JUDGE_GRAY_LOW, LLM_JUDGE_GRAY_HIGH = False, 0.35, 0.80

        self.block_threshold = block_threshold if block_threshold is not None else FUSION_BLOCK_THRESHOLD
        self.warn_threshold = warn_threshold if warn_threshold is not None else FUSION_WARN_THRESHOLD
        self.llm_judge_enabled = llm_judge_enabled if llm_judge_enabled is not None else LLM_JUDGE_ENABLED
        self.gray_low = gray_low if gray_low is not None else LLM_JUDGE_GRAY_LOW
        self.gray_high = gray_high if gray_high is not None else LLM_JUDGE_GRAY_HIGH

    @staticmethod
    def _fuse(scores: List[float]) -> float:
        """Strongest signal first, weaker ones add with diminishing returns."""
        scores = sorted([s for s in scores if s > 0], reverse=True)
        if not scores:
            return 0.0
        fused = scores[0]
        for i, s in enumerate(scores[1:], 1):
            fused += s * (0.35 ** i)
        return min(fused, 1.0)

    @staticmethod
    def _status(score: float, warn: float, block: float) -> str:
        if score >= block:
            return "block"
        if score >= warn:
            return "warn"
        return "pass"

    def screen(self, text: str) -> FusionResult:
        layers: List[LayerTrace] = []
        scores: List[float] = []
        categories: List[str] = []
        category_votes: Dict[str, float] = {}

        def vote(category: str, score: float):
            if category and category not in ("none", "unknown", ""):
                categories.append(category)
                category_votes[category] = max(category_votes.get(category, 0.0), score)

        # ---- Layer 1: regex / pattern matching ----------------------------
        regex_score = 0.0
        if self.input_guard is not None:
            res = self.input_guard.check(text)
            regex_score = res.threat_level
            cats = res.details.get("categories", []) if res.details else []
            for c in cats:
                vote(c, regex_score)
            layers.append(LayerTrace(
                name="Pattern Match",
                status=self._status(regex_score, self.warn_threshold, self.block_threshold),
                score=round(regex_score, 3),
                detail=", ".join(cats) if cats else "no signatures matched",
                category=cats[0] if cats else "",
            ))
            scores.append(regex_score)

        # ---- Layer 2: semantic similarity ---------------------------------
        sem_score = 0.0
        if self.semantic_guard is not None and getattr(self.semantic_guard, "enabled", False):
            sres = self.semantic_guard.check(text)
            sem_score = sres.score
            vote(sres.category, sem_score)
            sem_block = getattr(self.semantic_guard, "block_similarity", 0.62)
            sem_warn = getattr(self.semantic_guard, "warn_similarity", 0.45)
            layers.append(LayerTrace(
                name="Semantic Similarity",
                status=self._status(sem_score, sem_warn, sem_block),
                score=round(sem_score, 3),
                detail=(f"~{sres.category} ({sem_score:.0%} match)"
                        if sem_score >= sem_warn else "no semantic match"),
                category=sres.category,
            ))
            scores.append(sem_score)
        else:
            layers.append(LayerTrace(
                name="Semantic Similarity", status="skipped", score=0.0,
                detail="embedding model unavailable",
            ))

        # Provisional fusion from the two fast layers.
        provisional = self._fuse(scores)

        # ---- Layer 3: LLM judge (only for ambiguous "gray zone") ----------
        if (self.llm_judge_enabled and self.llm_judge is not None
                and self.gray_low <= provisional < self.gray_high):
            jres = self.llm_judge.judge(text)
            if jres.available:
                vote(jres.category, jres.score)
                layers.append(LayerTrace(
                    name="LLM Judge",
                    status=self._status(jres.score, self.warn_threshold, self.block_threshold),
                    score=round(jres.score, 3),
                    detail=f"{jres.verdict}: {jres.rationale}"[:140],
                    category=jres.category,
                ))
                scores.append(jres.score)
            else:
                layers.append(LayerTrace(
                    name="LLM Judge", status="skipped", score=0.0,
                    detail="judge unavailable / abstained",
                ))
        else:
            reason = "not enabled" if not self.llm_judge_enabled else "score outside gray zone"
            layers.append(LayerTrace(
                name="LLM Judge", status="skipped", score=0.0,
                detail=reason,
            ))

        # ---- Final fusion -------------------------------------------------
        threat_level = self._fuse(scores)
        decision = self._status(threat_level, self.warn_threshold, self.block_threshold)
        blocked = decision == "block"

        primary_category = ""
        if category_votes:
            primary_category = max(category_votes, key=lambda c: category_votes[c])
        reason = _REASON_MAP.get(primary_category, "Potentially harmful content detected") if blocked else ""

        return FusionResult(
            blocked=blocked,
            decision=decision,
            threat_level=round(threat_level, 3),
            reason=reason,
            primary_category=primary_category,
            layers=layers,
            categories=sorted(set(categories)),
            details={
                "regex_score": round(regex_score, 3),
                "semantic_score": round(sem_score, 3),
                "category_votes": {k: round(v, 3) for k, v in category_votes.items()},
            },
        )
