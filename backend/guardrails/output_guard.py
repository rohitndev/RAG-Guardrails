"""
Output guard for scanning and redacting unsafe LLM outputs.
"""
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple


@dataclass
class OutputCheckResult:
    """Result of output validation check."""
    blocked: bool
    had_issues: bool
    sanitized_content: str
    original_content: str
    issues: List[Dict[str, Any]] = field(default_factory=list)


class OutputGuard:
    """
    Scan and redact unsafe content from LLM outputs.
    """
    
    # Sensitive data patterns to redact
    SENSITIVE_PATTERNS = [
        # Email addresses
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "[EMAIL REDACTED]", "email"),
        
        # Phone numbers (various formats)
        (r'\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b', "[PHONE REDACTED]", "phone"),
        
        # SSN
        (r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', "[SSN REDACTED]", "ssn"),
        
        # Credit card numbers
        (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', "[CARD REDACTED]", "credit_card"),
        
        # API keys / tokens (common patterns)
        (r'\b(?:sk|pk|api|key|token|secret|password)[-_]?[A-Za-z0-9]{20,}\b', "[API_KEY REDACTED]", "api_key"),
        
        # AWS keys
        (r'\bAKIA[0-9A-Z]{16}\b', "[AWS_KEY REDACTED]", "aws_key"),
        
        # Private keys
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "[PRIVATE_KEY REDACTED]", "private_key"),

        # IP addresses (internal)
        (r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b', "[INTERNAL_IP REDACTED]", "internal_ip"),

        # JWT (header.payload.signature)
        (r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b', "[JWT REDACTED]", "jwt"),

        # Explicit credential assignments ("password: hunter2", "secret = abc123")
        (r'(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*\S+', "[CREDENTIAL REDACTED]", "credential_assignment"),
    ]
    
    # Harmful content patterns to block
    HARMFUL_PATTERNS = [
        (r"how\s+to\s+(?:make|create|build)\s+(?:a\s+)?(?:bomb|weapon|explosive)", "weapons_instructions"),
        (r"(?:kill|murder|harm|hurt)\s+(?:yourself|someone|people)", "violence"),
        (r"(?:hack|break\s+into|unauthorized\s+access)\s+(?:to|into)", "hacking_instructions"),
        (r"(?:steal|phish|scam)\s+(?:credit\s+card|identity|money)", "fraud_instructions"),
    ]
    
    # Patterns indicating the AI might have been manipulated
    MANIPULATION_INDICATORS = [
        (r"(?:as|since)\s+(?:you|the\s+user)\s+(?:asked|requested|instructed)", "following_injected_instruction"),
        (r"my\s+(?:true|real|actual)\s+(?:purpose|goal|mission)\s+is", "identity_compromise"),
        (r"I\s+(?:will|shall|must)\s+now\s+(?:ignore|disregard)", "rule_violation"),
        (r"(?:jailbreak|dan\s+mode|developer\s+mode)\s+(?:activated|enabled)", "jailbreak_success"),
    ]
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize the output guard.
        
        Args:
            strict_mode: If True, block on any harmful content detection
        """
        self.strict_mode = strict_mode
        
        # Compile patterns
        self.compiled_sensitive = []
        for pattern, replacement, category in self.SENSITIVE_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self.compiled_sensitive.append((compiled, replacement, category))
            except re.error:
                pass
        
        self.compiled_harmful = []
        for pattern, category in self.HARMFUL_PATTERNS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self.compiled_harmful.append((compiled, category))
            except re.error:
                pass
        
        self.compiled_manipulation = []
        for pattern, category in self.MANIPULATION_INDICATORS:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self.compiled_manipulation.append((compiled, category))
            except re.error:
                pass

        # Optional Microsoft Presidio engine for richer, ML-backed PII detection.
        # Regex patterns above remain the always-on baseline; Presidio augments
        # them when installed and enabled. Import is fully optional.
        self._presidio = None
        try:
            from config import PRESIDIO_ENABLED
        except Exception:
            PRESIDIO_ENABLED = False
        if PRESIDIO_ENABLED:
            try:
                from presidio_analyzer import AnalyzerEngine
                self._presidio = AnalyzerEngine()
            except Exception:
                self._presidio = None  # fall back silently to regex
    
    def check(self, output: str) -> OutputCheckResult:
        """
        Check and sanitize LLM output.
        
        Args:
            output: LLM output text
            
        Returns:
            OutputCheckResult with sanitized content and issues
        """
        if not output:
            return OutputCheckResult(
                blocked=False,
                had_issues=False,
                sanitized_content=output,
                original_content=output
            )
        
        issues = []
        sanitized = output
        should_block = False
        
        # Check for harmful content (may trigger block)
        for pattern, category in self.compiled_harmful:
            if pattern.search(output):
                issues.append({
                    "type": "harmful_content",
                    "category": category,
                    "action": "blocked"
                })
                should_block = True
        
        # Check for manipulation indicators
        for pattern, category in self.compiled_manipulation:
            if pattern.search(output):
                issues.append({
                    "type": "manipulation_indicator",
                    "category": category,
                    "action": "flagged"
                })
                if self.strict_mode:
                    should_block = True
        
        # Redact sensitive data (always, even if not blocking)
        for pattern, replacement, category in self.compiled_sensitive:
            matches = pattern.findall(sanitized)
            if matches:
                sanitized = pattern.sub(replacement, sanitized)
                issues.append({
                    "type": "sensitive_data",
                    "category": category,
                    "count": len(matches),
                    "action": "redacted"
                })

        # Optional Presidio pass — catches entities (names, locations, etc.)
        # the regex baseline does not model. Augments, never replaces, the regex.
        if self._presidio is not None:
            sanitized = self._apply_presidio(sanitized, issues)

        return OutputCheckResult(
            blocked=should_block,
            had_issues=len(issues) > 0,
            sanitized_content=sanitized,
            original_content=output,
            issues=issues
        )
    
    # Entities Presidio should redact (beyond what the regex layer covers).
    _PRESIDIO_ENTITIES = [
        "PERSON", "LOCATION", "EMAIL_ADDRESS", "PHONE_NUMBER",
        "CREDIT_CARD", "US_SSN", "IBAN_CODE", "IP_ADDRESS",
        "US_PASSPORT", "US_DRIVER_LICENSE", "CRYPTO",
    ]

    def _apply_presidio(self, text: str, issues: List[Dict[str, Any]]) -> str:
        """Redact PII entities found by Presidio, splicing from the end so spans stay valid."""
        try:
            results = self._presidio.analyze(
                text=text, entities=self._PRESIDIO_ENTITIES, language="en"
            )
        except Exception:
            return text

        # Keep only confident hits and redact right-to-left.
        hits = sorted(
            [r for r in results if getattr(r, "score", 0) >= 0.5],
            key=lambda r: r.start, reverse=True,
        )
        counts: Dict[str, int] = {}
        for r in hits:
            text = text[:r.start] + f"[{r.entity_type} REDACTED]" + text[r.end:]
            counts[r.entity_type] = counts.get(r.entity_type, 0) + 1

        for entity, count in counts.items():
            issues.append({
                "type": "sensitive_data",
                "category": f"presidio_{entity.lower()}",
                "count": count,
                "action": "redacted",
            })
        return text

    def redact_sensitive(self, text: str) -> str:
        """
        Redact only sensitive data from text.
        
        Args:
            text: Text to redact
            
        Returns:
            Text with sensitive data redacted
        """
        result = text
        for pattern, replacement, _ in self.compiled_sensitive:
            result = pattern.sub(replacement, result)
        return result
    
    def contains_harmful(self, text: str) -> bool:
        """
        Check if text contains harmful content.
        
        Args:
            text: Text to check
            
        Returns:
            True if harmful content detected
        """
        for pattern, _ in self.compiled_harmful:
            if pattern.search(text):
                return True
        return False
    
    def get_safety_report(self, output: str) -> Dict[str, Any]:
        """
        Generate a detailed safety report for output.
        
        Args:
            output: Output to analyze
            
        Returns:
            Safety report dictionary
        """
        result = self.check(output)
        
        return {
            "safe": not result.blocked and not result.had_issues,
            "blocked": result.blocked,
            "issues_found": len(result.issues),
            "issues": result.issues,
            "sensitive_data_redacted": any(
                i["type"] == "sensitive_data" for i in result.issues
            ),
            "harmful_content_detected": any(
                i["type"] == "harmful_content" for i in result.issues
            ),
            "manipulation_detected": any(
                i["type"] == "manipulation_indicator" for i in result.issues
            ),
            "original_length": len(output),
            "sanitized_length": len(result.sanitized_content)
        }
