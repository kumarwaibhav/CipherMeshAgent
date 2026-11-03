"""Autonomous CipherMesh agent: message dispatch, validated sync, and proactive commands."""
from __future__ import annotations
from collections import deque
from threading import RLock
from time import perf_counter
from .audit import AuditLog
from .detector import validate_custom_pattern
from .models import AgentState, AuditEvent, Decision, MessageType, WireMessage, utc_now
from .policy import inspect_text


class CipherMeshAgent:
    MAX_SEEN_MESSAGE_IDS = 4096

    def __init__(self, agent_id: str, audit_path: str = "ciphermesh_audit.db"):
        self.state = AgentState(agent_id=agent_id)
        self.audit = AuditLog(audit_path)
        self.approvals: dict[str, bool] = {}
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
            active_rules = ["R1", "R2", "R3", "R4", "R5"]
            return {
                "agent_id": self.state.agent_id,
                "policy_version": self.state.policy_version,
                "policy_revision": self.state.policy_revision,
                "current_policy_mode": mode,
                "active_rules": active_rules,
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
        # Serialize all state mutations and message-id replay checks across worker threads.
        with self._lock:
            return self._handle_locked(message)

    def _handle_locked(self, message: WireMessage) -> dict:
        if message.recipient != self.state.agent_id:
            return self._error(message, "recipient mismatch")
        if message.message_id in self._seen_ids:
            return self._error(message, "duplicate message_id rejected")
        self._remember_id(message.message_id)
        self.state.sequence += 1
        self.audit.write(AuditEvent(agent_id=self.state.agent_id, event_type="message_received",
                                    message_id=message.message_id,
                                    details={"type": message.message_type.value, "sender": message.sender}))
        if message.message_type == MessageType.PING:
            return self._reply(message, MessageType.ACK, {"status": "ok", "agent_id": self.state.agent_id,
                                                          "policy_revision": self.state.policy_revision})
        if message.message_type == MessageType.STATE_SYNC:
            return self._handle_state_sync(message)
        if message.message_type == MessageType.INSPECT:
            text = message.payload.get("text")
            if not isinstance(text, str):
                return self._error(message, "INSPECT requires payload.text string")
            result = self._inspect_locked(text, message.message_id)
            return self._reply(message, MessageType.ACK, {"inspection": result.model_dump(mode="json")})
        if message.message_type == MessageType.COMMAND_INSTRUCTION:
            return self._handle_command(message)
        if message.message_type == MessageType.APPROVAL:
            correlation = message.correlation_id
            approved = message.payload.get("approved")
            if not correlation or not isinstance(approved, bool):
                return self._error(message, "APPROVAL requires correlation_id and boolean approved")
            self.approvals[correlation] = approved
            return self._reply(message, MessageType.ACK, {"status": "approval_recorded",
                                                          "correlation_id": correlation, "approved": approved})
        if message.message_type == MessageType.POLICY_UPDATE:
            return self._error(message, "use STATE_SYNC or COMMAND_INSTRUCTION for validated updates")
        return self._error(message, f"unsupported message type: {message.message_type.value}")

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

    def _inspect_locked(self, text: str, message_id: str | None = None):
        started = perf_counter()
        result = inspect_text(text, self.state)
        elapsed_ms = (perf_counter() - started) * 1000.0
        self.metrics["total_inspected_prompts"] += 1
        self.metrics["total_inspection_latency_ms"] += elapsed_ms
        if result.decision == Decision.BLOCK:
            self.metrics["total_secrets_blocked"] += 1
        elif result.decision == Decision.REDACT:
            self.metrics["total_pii_redacted"] += 1
        elif result.decision == Decision.REVIEW:
            self.metrics["total_reviews_required"] += 1
        elif result.decision == Decision.ALLOW:
            self.metrics["total_allowed"] += 1
        self.audit.write(AuditEvent(agent_id=self.state.agent_id, event_type="inspection",
            decision=result.decision, categories=[finding.category for finding in result.findings],
            message_id=message_id,
            details={"finding_count": len(result.findings), "reasons": result.reasons,
                     "latency_ms": round(elapsed_ms, 3)}))
        return result

    def inspect(self, text: str):
        with self._lock:
            return self._inspect_locked(text)

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
