from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from ciphermesh_concurrent_agent import CipherMeshConcurrentAgent, LLMRequest, decide, inspect


class CipherMeshConcurrencyTests(unittest.TestCase):
    def test_assignment_1_2_policy_is_preserved(self):
        findings, _ = inspect("Contact a@example.com and check AKIAIOSFODNN7EXAMPLE")
        decision, _ = decide(findings)
        self.assertEqual(decision, "BLOCK")

    def test_redaction_is_safe(self):
        secret_email = "student@example.com"
        findings, sanitized = inspect(f"Email {secret_email} or call +91 9876543210")
        self.assertEqual(decide(findings)[0], "REDACT")
        self.assertNotIn(secret_email, sanitized)
        self.assertIn("[EMAIL_REDACTED]", sanitized)

    def test_concurrent_exactly_once_accounting_and_shutdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = CipherMeshConcurrentAgent(
                worker_count=4,
                queue_size=16,
                monitor_interval_s=0.01,
                simulate_provider_ms=2,
                log_dir=Path(tmp),
                console_enabled=False,
            )
            agent.start()
            for i in range(50):
                agent.state.mark_parsed()
                agent.submit_request(
                    LLMRequest(
                        timestamp="2026-09-02T10:00:00+05:30",
                        request_id=f"T-{i:03d}",
                        provider="ollama-local",
                        model="gemma3",
                        prompt="Explain worker queues.",
                    )
                )
            agent.wait_until_idle(0.001)
            results = agent.collect_results()
            snapshot = agent.close()
            self.assertEqual(len(results), 50)
            self.assertEqual(snapshot["completed"], 50)
            self.assertEqual(snapshot["ALLOW"], 50)
            self.assertEqual(snapshot["in_flight"], 0)
            self.assertTrue(all(not worker.is_alive() for worker in agent.workers))

    def test_privacy_safe_audit_never_contains_original_secret(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            agent = CipherMeshConcurrentAgent(
                worker_count=2,
                monitor_interval_s=0.01,
                simulate_provider_ms=1,
                log_dir=log_dir,
                console_enabled=False,
            )
            agent.start()
            agent.state.mark_parsed()
            agent.submit_request(
                LLMRequest(
                    timestamp="2026-09-02T10:00:00+05:30",
                    request_id="SECRET-1",
                    provider="aws-bedrock",
                    model="demo",
                    prompt=f"Debug {secret}",
                )
            )
            agent.close()
            text = (log_dir / "audit_events.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(secret, text)
            self.assertIn("[AWS_ACCESS_KEY_REDACTED]", text)

    def test_monitor_daemon_writes_health_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            agent = CipherMeshConcurrentAgent(
                worker_count=2,
                monitor_interval_s=0.005,
                simulate_provider_ms=20,
                log_dir=log_dir,
                console_enabled=False,
            )
            agent.start()
            for i in range(6):
                agent.state.mark_parsed()
                agent.submit_request(
                    LLMRequest(
                        timestamp="2026-09-02T10:00:00+05:30",
                        request_id=f"M-{i}",
                        provider="ollama-local",
                        model="gemma3",
                        prompt="Safe prompt",
                    )
                )
            agent.close()
            lines = (log_dir / "monitor_metrics.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertGreaterEqual(len(lines), 2)
            records = [json.loads(line) for line in lines]
            self.assertEqual(records[0]["status"], "STARTING")
            self.assertEqual(records[-1]["status"], "STOPPED")
            self.assertIn("queue_depth", records[-1])
            self.assertIn("avg_service_ms", records[-1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
