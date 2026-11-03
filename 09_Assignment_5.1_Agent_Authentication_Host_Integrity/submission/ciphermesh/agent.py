"""Autonomous CipherMesh agent: message dispatch, validated sync, and proactive commands."""
from __future__ import annotations
from collections import deque
from threading import RLock
from typing import Any, Callable
from .audit import AuditLog
from .detector import validate_custom_pattern
from .models import AgentState, AuditEvent, Decision, InspectionResult, MessageType, WireMessage, utc_now
from .policy import inspect_text
from .review import ReviewError, ReviewQueue

ProcessHandler = Callable[[str, str | None, str | None], dict[str, Any]]
ApprovalHandler = Callable[[str, bool, str], dict[str, Any]]


class CipherMeshAgent:
    MAX_SEEN_MESSAGE_IDS = 4096

    def __init__(self, agent_id: str, audit_path: str = "ciphermesh_audit.db",
                 review_queue: ReviewQueue | None = None):
        self.state = AgentState(agent_id=agent_id)
        self.audit = AuditLog(audit_path)
        self.reviews = review_queue or ReviewQueue()
        self.approvals: dict[str, bool] = {}
        self.process_handler: ProcessHandler | None = None
        self.approval_handler: ApprovalHandler | None = None
        self.metrics = {
            "total_inspected_prompts": 0,
            "total_secrets_blocked": 0,
            "total_pii_redacted": 0,
            "total_reviews_required": 0,
            "total_allowed": 0,
            "total_inspection_latency_ms": 0.0,
        }
        self._lock = RLock()
        self._seen_ids: set[str] = set()
        self._seen_order: deque[str] = deque()

    def safe_state_payload(self) -> dict:
        """Explicit safe allow-list; never includes prompt text, matched values or auth tokens."""
        with self._lock:
            mode = "FORCE_BLOCK_ALL" if self.state.force_block_all else "STRICT"
            return {
                "agent_id": self.state.agent_id,
                "policy_version": self.state.policy_version,
                "policy_revision": self.state.policy_revision,
                "current_policy_mode": mode,
                "active_rules": ["R1", "R2", "R3", "R4", "R5"],
                "provider_allowlist": list(self.state.provider_allowlist),
                "max_prompt_bytes": self.state.max_prompt_bytes,
                "require_review_for_internal_urls": self.state.require_review_for_internal_urls,
                "redact_email_phone_ip": self.state.redact_email_phone_ip,
                "block_critical_secrets": self.state.block_critical_secrets,
                "custom_redaction_patterns": list(self.state.custom_redaction_patterns),
                "sequence": self.state.sequence,
                "updated_at": self.state.updated_at.isoformat(),
                "metrics": self._metrics_payload_locked(),
            }

    def _metrics_payload_locked(self) -> dict:
        count = self.metrics["total_inspected_prompts"]
        mean = self.metrics["total_inspection_latency_ms"] / count if count else 0.0
        return {
            "total_inspected_prompts": count,
            "total_secrets_blocked": self.metrics["total_secrets_blocked"],
            "total_pii_redacted": self.metrics["total_pii_redacted"],
            "total_reviews_required": self.metrics["total_reviews_required"],
            "total_allowed": self.metrics["total_allowed"],
            "mean_latency_ms": round(mean, 3),
        }

    def handle(self, message: WireMessage) -> dict:
        # Replay checks and state mutation are serialized; PROCESS runs its provider I/O outside the lock.
        with self._lock:
            reply = self._handle_locked(message)
        if not isinstance(reply, tuple):
            return reply
        try:
            if reply[0] == "PROCESS":
                assert self.process_handler is not None
                return self._reply(message, MessageType.ACK,
                                   {"outcome": self.process_handler(reply[1], reply[2], reply[3])})
            assert self.approval_handler is not None
            outcome = self.approval_handler(reply[1], reply[2], reply[3])
            return self._reply(message, MessageType.ACK, {"status": "review_decided", "outcome": outcome})
        except ReviewError as exc:
            return self._error(message, str(exc))
        except Exception as exc:  # contain handler faults at the trust boundary
            return self._error(message, f"processing failed: {type(exc).__name__}")

    def _handle_locked(self, message: WireMessage):
        if message.recipient != self.state.agent_id:
            return self._error(message, "recipient mismatch")
        if message.message_id in self._seen_ids:
            return self._error(message, "duplicate message_id rejected")
        self._remember_id(message.message_id)
        self.state.sequence += 1
        self.audit.write(AuditEvent(agent_id=self.state.agent_id, event_type="message_received",
                                    message_id=message.message_id,
                                    details={"type": message.message_type.value, "sender": message.sender}))
        kind = message.message_type
        if kind == MessageType.PING:
            return self._reply(message, MessageType.ACK, {"status": "ok", "agent_id": self.state.agent_id,
                                                          "policy_revision": self.state.policy_revision})
        if kind == MessageType.STATE_SYNC:
            return self._handle_state_sync(message)
        if kind == MessageType.INSPECT:
            text = message.payload.get("text")
            if not isinstance(text, str):
                return self._error(message, "INSPECT requires payload.text string")
            result = self._inspect_locked(text, message.message_id)
            return self._reply(message, MessageType.ACK, {"inspection": result.model_dump(mode="json")})
        if kind == MessageType.PROCESS:
            text = message.payload.get("text")
            provider = message.payload.get("provider")
            if not isinstance(text, str) or (provider is not None and not isinstance(provider, str)):
                return self._error(message, "PROCESS requires payload.text string and optional provider string")
            if self.process_handler is None:
                return self._error(message, "this agent has no orchestration pipeline attached")
            return ("PROCESS", text, provider, message.message_id)
        if kind == MessageType.COMMAND_INSTRUCTION:
            return self._handle_command(message)
        if kind == MessageType.APPROVAL:
            return self._handle_approval(message)
        if kind == MessageType.POLICY_UPDATE:
            return self._error(message, "use STATE_SYNC or COMMAND_INSTRUCTION for validated updates")
        return self._error(message, f"unsupported message type: {kind.value}")

    def _handle_approval(self, message: WireMessage) -> dict:
        correlation = message.correlation_id or message.payload.get("review_id")
        approved = message.payload.get("approved")
        reviewer = message.payload.get("reviewer") or message.sender
        if not correlation or not isinstance(approved, bool):
            return self._error(message, "APPROVAL requires correlation_id/review_id and boolean approved")
        self.approvals[correlation] = approved
        if self.reviews.get(correlation) is None:
            return self._reply(message, MessageType.ACK, {"status": "approval_recorded",
                                                          "correlation_id": correlation, "approved": approved})
        if self.approval_handler is not None:
            return ("APPROVAL", correlation, approved, str(reviewer))
        try:
            ticket, _ = self.reviews.decide(correlation, approved, str(reviewer))
        except ReviewError as exc:
            return self._error(message, str(exc))
        self.audit.write(AuditEvent(agent_id=self.state.agent_id, event_type="review_decided",
                                    message_id=message.message_id,
                                    details={"review_id": correlation, "status": ticket.status.value}))
        return self._reply(message, MessageType.ACK, {"status": "review_decided",
                                                      "ticket": ticket.model_dump(mode="json")})

    def _handle_state_sync(self, message: WireMessage) -> dict:
        incoming = message.payload.get("state")
        if not isinstance(incoming, dict):
            return self._error(message, "STATE_SYNC requires payload.state object")
        allowed = {
            "policy_version", "policy_revision", "provider_allowlist", "max_prompt_bytes",
            "require_review_for_internal_urls", "redact_email_phone_ip", "block_critical_secrets",
            "custom_redaction_patterns",
        }
        changes = {key: value for key, value in incoming.items() if key in allowed}
        if "policy_revision" not in changes:
            return self._error(message, "STATE_SYNC requires an integer policy_revision")
        try:
            proposed_revision = int(changes["policy_revision"])
        except (ValueError, TypeError):
            return self._error(message, "policy_revision must be an integer")
        if proposed_revision < self.state.policy_revision:
            return self._error(message, "stale policy revision rejected")
        if proposed_revision == self.state.policy_revision:
            same = all(getattr(self.state, key) == value for key, value in changes.items()
                       if key != "policy_revision")
            if same:
                return self._reply(message, MessageType.ACK, {
                    "status": "state_unchanged", "state": self.safe_state_payload()
                })
            return self._error(message, "same policy revision cannot change policy fields")

        patterns = changes.get("custom_redaction_patterns", self.state.custom_redaction_patterns)
        validation_error = self._validate_patterns(patterns)
        if validation_error:
            return self._error(message, validation_error)
        candidate_data = self.state.model_dump()
        candidate_data.update(changes)
        # Identity, sequence, and lockdown are local controls, never remotely overwritten.
        candidate_data["agent_id"] = self.state.agent_id
        candidate_data["sequence"] = self.state.sequence
        candidate_data["force_block_all"] = self.state.force_block_all
        candidate_data["updated_at"] = utc_now()
        try:
            candidate = AgentState.model_validate(candidate_data)
        except Exception:
            return self._error(message, "invalid state fields")
        self.state = candidate
        self.audit.write(AuditEvent(agent_id=self.state.agent_id, event_type="state_sync_applied",
                                    message_id=message.message_id,
                                    details={"revision": self.state.policy_revision,
                                             "fields": sorted(changes.keys())}))
        return self._reply(message, MessageType.ACK, {
            "status": "state_applied", "applied_fields": sorted(changes.keys()),
            "state": self.safe_state_payload()
        })

    def _handle_command(self, message: WireMessage) -> dict:
        command = message.payload.get("command")
        if command == "TRIGGER_EMERGENCY_LOCKDOWN":
            self.state.force_block_all = True
            self.state.updated_at = utc_now()
            self.audit.write(AuditEvent(agent_id=self.state.agent_id, event_type="emergency_lockdown_enabled",
                                        message_id=message.message_id, details={"mode": "FORCE_BLOCK_ALL"}))
            return self._reply(message, MessageType.ACK, {
                "status": "lockdown_enabled", "current_policy_mode": "FORCE_BLOCK_ALL"
            })

        if command == "UPDATE_REDACTION_PATTERNS":
            incoming = message.payload.get("patterns")
            if not isinstance(incoming, list) or not incoming or len(incoming) > 32:
                return self._error(message, "patterns must be a non-empty list of at most 32 strings")
            error = self._validate_patterns(incoming)
            if error:
                return self._error(message, error)
            combined = list(dict.fromkeys([*self.state.custom_redaction_patterns, *incoming]))
            if len(combined) > 32:
                return self._error(message, "combined custom pattern limit is 32")
            self.state.custom_redaction_patterns = combined
            self.state.updated_at = utc_now()
            self.audit.write(AuditEvent(agent_id=self.state.agent_id, event_type="redaction_patterns_updated",
                                        message_id=message.message_id,
                                        details={"pattern_count": len(combined)}))
            return self._reply(message, MessageType.ACK, {
                "status": "patterns_updated", "custom_redaction_pattern_count": len(combined)
            })

        if command == "REQUEST_TELEMETRY_DUMP":
            # Telemetry is an allow-listed snapshot: no prompts, matches, PII or auth material.
            return self._reply(message, MessageType.ACK, {
                "status": "telemetry_ready", "telemetry": self.safe_state_payload()
            })

        if command == "LIST_PENDING_REVIEWS":
            pending = [t.model_dump(mode="json") for t in self.reviews.list() if t.status.value == "PENDING"]
            return self._reply(message, MessageType.ACK, {"status": "reviews_listed", "reviews": pending})

        return self._error(message, "unsupported or missing proactive command")

    @staticmethod
    def _validate_patterns(patterns) -> str | None:
        if not isinstance(patterns, list) or len(patterns) > 32:
            return "custom_redaction_patterns must be a list of at most 32 patterns"
        for pattern in patterns:
            error = validate_custom_pattern(pattern)
            if error:
                return f"invalid redaction pattern: {error}"
        return None

    def _inspect_locked(self, text: str, message_id: str | None = None,
                        provider: str | None = None, open_review: bool = True) -> InspectionResult:
        result = inspect_text(text, self.state)
        elapsed_ms = result.latency_ms or 0.0
        self.metrics["total_inspected_prompts"] += 1
        self.metrics["total_inspection_latency_ms"] += elapsed_ms
        if result.decision == Decision.BLOCK:
            self.metrics["total_secrets_blocked"] += 1
        elif result.decision == Decision.REDACT:
            self.metrics["total_pii_redacted"] += 1
        elif result.decision == Decision.REVIEW:
            self.metrics["total_reviews_required"] += 1
            if open_review:
                try:
                    ticket = self.reviews.submit(text, [f.category for f in result.findings],
                                                 result.reasons, result.safe_preview, provider)
                    result.review_id = ticket.review_id
                except ReviewError as exc:
                    result = result.model_copy(update={"decision": Decision.BLOCK,
                                                       "reasons": [*result.reasons, str(exc)]})
        elif result.decision == Decision.ALLOW:
            self.metrics["total_allowed"] += 1
        self.audit.write(AuditEvent(agent_id=self.state.agent_id, event_type="inspection",
            decision=result.decision, categories=[finding.category for finding in result.findings],
            message_id=message_id,
            details={"finding_count": len(result.findings), "reasons": result.reasons,
                     "latency_ms": round(elapsed_ms, 3), "review_id": result.review_id}))
        return result

    def inspect(self, text: str, provider: str | None = None, open_review: bool = True) -> InspectionResult:
        with self._lock:
            return self._inspect_locked(text, provider=provider, open_review=open_review)

    def inspect_response(self, text: str) -> InspectionResult:
        """Response-side inspection: same detectors; never opens review tickets."""
        result = inspect_text(text, self.state.model_copy(update={"force_block_all": False}))
        self.audit.write(AuditEvent(agent_id=self.state.agent_id, event_type="response_inspection",
                                    decision=result.decision,
                                    categories=[f.category for f in result.findings],
                                    details={"finding_count": len(result.findings)}))
        return result

    def _remember_id(self, message_id: str) -> None:
        self._seen_ids.add(message_id)
        self._seen_order.append(message_id)
        while len(self._seen_order) > self.MAX_SEEN_MESSAGE_IDS:
            expired = self._seen_order.popleft()
            self._seen_ids.discard(expired)

    def _reply(self, request: WireMessage, kind: MessageType, payload: dict) -> dict:
        return WireMessage(message_type=kind, sender=self.state.agent_id, recipient=request.sender,
                           correlation_id=request.message_id, payload=payload).model_dump(mode="json")

    def _error(self, request: WireMessage, detail: str) -> dict:
        return self._reply(request, MessageType.ERROR, {"error": detail})
