"""
Security logger for recording guardrail events.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import threading

import sys
sys.path.append('..')
from config import LOGS_DIR


@dataclass
class SecurityEvent:
    """Represents a security event."""
    timestamp: str
    event_type: str
    input_text: str
    details: Dict[str, Any]
    threat_level: float = 0.0
    action_taken: str = ""
    session_id: str = ""


class SecurityLogger:
    """
    Log security events from guardrails for audit and analysis.
    """
    
    def __init__(self, log_dir: Optional[Path] = None):
        """
        Initialize the security logger.
        
        Args:
            log_dir: Directory to store log files
        """
        self.log_dir = log_dir or LOGS_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.log_file = self.log_dir / "security_events.json"
        self.events: List[SecurityEvent] = []
        self._lock = threading.Lock()
        
        # Load existing events
        self._load_events()
    
    def _load_events(self):
        """Load existing events from log file."""
        if self.log_file.exists():
            try:
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.events = [SecurityEvent(**e) for e in data]
            except (json.JSONDecodeError, Exception) as e:
                print(f"Warning: Could not load security events: {e}")
                self.events = []
    
    def _save_events(self):
        """Save events to log file."""
        try:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump([asdict(e) for e in self.events], f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save security events: {e}")
    
    def log_event(
        self,
        event_type: str,
        input_text: str,
        details: Dict[str, Any],
        threat_level: float = 0.0,
        action_taken: str = "",
        session_id: str = ""
    ) -> SecurityEvent:
        """
        Log a security event.
        
        Args:
            event_type: Type of event (e.g., "INPUT_BLOCKED", "OUTPUT_SANITIZED")
            input_text: The input that triggered the event
            details: Additional details about the event
            threat_level: Threat level (0.0 to 1.0)
            action_taken: What action was taken
            session_id: Optional session identifier
            
        Returns:
            The created SecurityEvent
        """
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            input_text=input_text[:500] if input_text else "",  # Truncate long inputs
            details=details,
            threat_level=threat_level,
            action_taken=action_taken,
            session_id=session_id
        )
        
        with self._lock:
            self.events.append(event)
            self._save_events()
        
        return event
    
    def log_input_blocked(
        self,
        input_text: str,
        reason: str,
        threat_level: float,
        patterns_matched: List[str] = None
    ) -> SecurityEvent:
        """
        Log a blocked input event.
        
        Args:
            input_text: The blocked input
            reason: Reason for blocking
            threat_level: Threat level
            patterns_matched: List of matched patterns
            
        Returns:
            The created SecurityEvent
        """
        return self.log_event(
            event_type="INPUT_BLOCKED",
            input_text=input_text,
            details={
                "reason": reason,
                "patterns_matched": patterns_matched or []
            },
            threat_level=threat_level,
            action_taken="blocked"
        )
    
    def log_output_sanitized(
        self,
        input_text: str,
        issues_found: List[Dict[str, Any]],
        was_blocked: bool = False
    ) -> SecurityEvent:
        """
        Log an output sanitization event.
        
        Args:
            input_text: The query that produced the output
            issues_found: Issues found in the output
            was_blocked: Whether the output was completely blocked
            
        Returns:
            The created SecurityEvent
        """
        return self.log_event(
            event_type="OUTPUT_SANITIZED" if not was_blocked else "OUTPUT_BLOCKED",
            input_text=input_text,
            details={"issues": issues_found},
            action_taken="blocked" if was_blocked else "sanitized"
        )
    
    def log_document_sanitized(
        self,
        source_file: str,
        instructions_removed: int,
        chunk_index: int = -1
    ) -> SecurityEvent:
        """
        Log a document sanitization event.
        
        Args:
            source_file: Source file name
            instructions_removed: Number of instructions removed
            chunk_index: Which chunk was sanitized
            
        Returns:
            The created SecurityEvent
        """
        return self.log_event(
            event_type="DOCUMENT_SANITIZED",
            input_text=source_file,
            details={
                "instructions_removed": instructions_removed,
                "chunk_index": chunk_index
            },
            action_taken="sanitized"
        )
    
    def log_prompt_override_blocked(
        self,
        attempted_prompt: str,
        session_id: str = ""
    ) -> SecurityEvent:
        """
        Log a blocked system prompt override attempt.
        
        Args:
            attempted_prompt: The prompt that was attempted
            session_id: Session identifier
            
        Returns:
            The created SecurityEvent
        """
        return self.log_event(
            event_type="PROMPT_OVERRIDE_BLOCKED",
            input_text=attempted_prompt,
            details={"type": "system_prompt_override"},
            threat_level=0.7,
            action_taken="blocked",
            session_id=session_id
        )
    
    def get_events(
        self,
        event_type: Optional[str] = None,
        min_threat_level: float = 0.0,
        limit: int = 100
    ) -> List[SecurityEvent]:
        """
        Get logged events with optional filtering.
        
        Args:
            event_type: Filter by event type
            min_threat_level: Minimum threat level to include
            limit: Maximum number of events to return
            
        Returns:
            List of matching events
        """
        with self._lock:
            filtered = self.events
            
            if event_type:
                filtered = [e for e in filtered if e.event_type == event_type]
            
            if min_threat_level > 0:
                filtered = [e for e in filtered if e.threat_level >= min_threat_level]
            
            # Return most recent first
            return sorted(
                filtered,
                key=lambda e: e.timestamp,
                reverse=True
            )[:limit]
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of security events.
        
        Returns:
            Summary statistics
        """
        with self._lock:
            if not self.events:
                return {
                    "total_events": 0,
                    "events_by_type": {},
                    "avg_threat_level": 0.0,
                    "high_threat_count": 0
                }
            
            events_by_type = {}
            total_threat = 0.0
            high_threat_count = 0
            
            for event in self.events:
                events_by_type[event.event_type] = events_by_type.get(event.event_type, 0) + 1
                total_threat += event.threat_level
                if event.threat_level >= 0.7:
                    high_threat_count += 1
            
            return {
                "total_events": len(self.events),
                "events_by_type": events_by_type,
                "avg_threat_level": total_threat / len(self.events),
                "high_threat_count": high_threat_count,
                "first_event": self.events[0].timestamp if self.events else None,
                "last_event": self.events[-1].timestamp if self.events else None
            }
    
    def get_analytics(self) -> Dict[str, Any]:
        """
        Build an aggregated analytics payload for the security dashboard.

        Returns time-bucketed activity, attack-category and event-type
        breakdowns, a threat-level histogram, and headline KPIs.
        """
        with self._lock:
            events = list(self.events)

        if not events:
            return {
                "kpis": {
                    "total_events": 0, "blocked_count": 0, "block_rate": 0.0,
                    "avg_threat_level": 0.0, "high_threat_count": 0,
                    "sanitized_count": 0,
                },
                "events_by_type": {},
                "events_by_category": {},
                "threat_histogram": {"low": 0, "medium": 0, "high": 0},
                "timeline": [],
                "recent_high_threat": [],
            }

        events_by_type: Dict[str, int] = {}
        events_by_category: Dict[str, int] = {}
        histogram = {"low": 0, "medium": 0, "high": 0}
        timeline_buckets: Dict[str, Dict[str, int]] = {}

        blocked_count = 0
        sanitized_count = 0
        total_threat = 0.0
        high_threat_count = 0

        for e in events:
            events_by_type[e.event_type] = events_by_type.get(e.event_type, 0) + 1

            if e.action_taken == "blocked":
                blocked_count += 1
            elif e.action_taken == "sanitized":
                sanitized_count += 1

            total_threat += e.threat_level
            if e.threat_level >= 0.7:
                high_threat_count += 1

            # Threat histogram
            if e.threat_level >= 0.7:
                histogram["high"] += 1
            elif e.threat_level >= 0.4:
                histogram["medium"] += 1
            else:
                histogram["low"] += 1

            # Attack categories (stored under a few possible detail keys)
            cats = []
            if isinstance(e.details, dict):
                cats = (e.details.get("categories")
                        or e.details.get("patterns_matched")
                        or [])
                if isinstance(cats, str):
                    cats = [cats]
            for c in cats:
                events_by_category[c] = events_by_category.get(c, 0) + 1

            # Timeline bucketed by hour (minute precision in the timestamp string)
            bucket = e.timestamp[:13] if len(e.timestamp) >= 13 else e.timestamp
            slot = timeline_buckets.setdefault(bucket, {"total": 0, "blocked": 0})
            slot["total"] += 1
            if e.action_taken == "blocked":
                slot["blocked"] += 1

        timeline = [
            {"time": k, "total": v["total"], "blocked": v["blocked"]}
            for k, v in sorted(timeline_buckets.items())
        ]

        recent_high = sorted(
            [e for e in events if e.threat_level >= 0.7],
            key=lambda e: e.timestamp, reverse=True,
        )[:8]
        recent_high_threat = [
            {
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "threat_level": e.threat_level,
                "preview": (e.input_text[:80] + "...") if len(e.input_text) > 80 else e.input_text,
            }
            for e in recent_high
        ]

        total = len(events)
        return {
            "kpis": {
                "total_events": total,
                "blocked_count": blocked_count,
                "sanitized_count": sanitized_count,
                "block_rate": round(blocked_count / total, 3) if total else 0.0,
                "avg_threat_level": round(total_threat / total, 3) if total else 0.0,
                "high_threat_count": high_threat_count,
            },
            "events_by_type": events_by_type,
            "events_by_category": events_by_category,
            "threat_histogram": histogram,
            "timeline": timeline,
            "recent_high_threat": recent_high_threat,
        }

    def clear_events(self):
        """Clear all logged events."""
        with self._lock:
            self.events = []
            self._save_events()
    
    def export_to_file(self, filepath: Path) -> bool:
        """
        Export events to a specific file.
        
        Args:
            filepath: Path to export to
            
        Returns:
            Whether export was successful
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump([asdict(e) for e in self.events], f, indent=2)
            return True
        except Exception as e:
            print(f"Error exporting events: {e}")
            return False
