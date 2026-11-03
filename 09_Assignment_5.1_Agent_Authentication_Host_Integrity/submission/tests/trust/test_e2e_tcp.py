"""End-to-end over real TCP loopback with distinct, kernel-reported source addresses.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
import socket
from concurrent.futures import ThreadPoolExecutor

import pytest

from ciphermesh.trust import commands as cmd
from ciphermesh.trust.client import SecureClient
from ciphermesh.trust.secure_server import BackgroundServer

from .helpers import ADMIN_IP, OBSERVER_IP


@pytest.fixture
def running(make_agent):
    agent = make_agent()
    with BackgroundServer(agent) as server:
        yield agent, server.port


def test_signed_command_accepted_over_tcp_and_reply_verified(prov, ids, running):
    agent, port = running
    client = SecureClient(ids["sec-console-01"], agent.trust, port, source_ip=ADMIN_IP)
    reply = client.send_envelope(client.command(cmd.TRIGGER_EMERGENCY_LOCKDOWN, {"reason": "e2e"}))
    assert reply.verified and reply.status == "ACCEPTED" and agent.engine.state.force_block_all
    assert agent.history[-1].verdict.origin.address == ADMIN_IP


def test_same_valid_key_from_untrusted_source_is_rejected(prov, ids, running):
    agent, port = running
    client = SecureClient(ids["sec-console-01"], agent.trust, port, source_ip="127.0.0.66")
    reply = client.send_envelope(client.command(cmd.TRIGGER_EMERGENCY_LOCKDOWN, {"reason": "stolen key"}))
    assert reply.verified and reply.status == "REJECTED"
    assert agent.history[-1].verdict.checkpoint == "C7" and not agent.engine.state.force_block_all


def test_oversized_and_malformed_frames_do_not_kill_the_server(prov, ids, running):
    agent, port = running
    client = SecureClient(ids["observer-01"], agent.trust, port, source_ip=OBSERVER_IP)
    assert client.send_raw(b"", declared_length=5_000_000).status == "REJECTED"
    assert agent.history[-1].verdict.reason == "FRAME_TOO_LARGE"
    assert client.send_raw(b'{"header": {').status == "REJECTED"
    assert agent.history[-1].verdict.reason == "JSON_MALFORMED"
    assert client.send_envelope(client.command(cmd.REQUEST_TELEMETRY_DUMP)).status == "ACCEPTED"


def test_replay_over_tcp_is_rejected(prov, ids, running):
    agent, port = running
    client = SecureClient(ids["observer-01"], agent.trust, port, source_ip=OBSERVER_IP)
    env = client.command(cmd.REQUEST_TELEMETRY_DUMP)
    assert client.send_envelope(env).status == "ACCEPTED"
    assert client.send_envelope(env).status == "REJECTED"
    assert agent.history[-1].verdict.reason == "REPLAY_MSG_ID"


def test_concurrent_clients_are_all_verified(prov, ids, make_agent):
    from ciphermesh.trust.secure_agent import AgentConfig
    agent = make_agent(config=AgentConfig(lockout_threshold=1000, max_connections_per_ip=8))
    with BackgroundServer(agent) as server:
        client = SecureClient(ids["observer-01"], agent.trust, server.port, source_ip=OBSERVER_IP)
        with ThreadPoolExecutor(max_workers=8) as pool:
            replies = list(pool.map(lambda _: client.send_envelope(client.command(cmd.REQUEST_TELEMETRY_DUMP)),
                                    range(16)))
    assert all(r.verified and r.status == "ACCEPTED" for r in replies)


def test_half_open_connection_is_dropped_without_crash(prov, ids, running):
    agent, port = running
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.sendall(b"\x00\x00")
    client = SecureClient(ids["observer-01"], agent.trust, port, source_ip="127.0.0.70")
    assert client.send_raw(b"{}").status == "REJECTED"
    assert agent.history[-1].verdict.checkpoint == "C2"


def test_slow_clients_hit_the_frame_deadline_and_per_ip_cap(prov, ids, make_agent):
    import time
    from ciphermesh.trust.secure_agent import AgentConfig
    agent = make_agent(config=AgentConfig(lockout_threshold=1000, frame_deadline_s=0.6, max_connections_per_ip=2))
    with BackgroundServer(agent) as server:
        drips = []
        for _ in range(3):
            sock = socket.socket()
            sock.bind(("127.0.0.67", 0))
            sock.connect(("127.0.0.1", server.port))
            sock.sendall(b"\x00")
            drips.append(sock)
        client = SecureClient(ids["observer-01"], agent.trust, server.port, source_ip=OBSERVER_IP)
        started = time.monotonic()
        assert client.send_envelope(client.command(cmd.REQUEST_TELEMETRY_DUMP)).status == "ACCEPTED"
        assert time.monotonic() - started < 0.5                       # other peers are not starved
        time.sleep(1.0)
        for sock in drips:
            sock.close()
    reasons = sorted(e["reason"] for e in agent.audit.events if e.get("checkpoint") == "L0")
    assert reasons == ["CONNECTION_LIMIT", "FRAME_TIMEOUT", "FRAME_TIMEOUT"]
