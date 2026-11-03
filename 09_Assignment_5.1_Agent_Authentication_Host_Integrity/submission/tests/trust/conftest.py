"""Shared fixtures for the Assignment 5.1 trust-layer tests.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
from __future__ import annotations

import pytest

from ciphermesh.trust.integrity import load_signed_manifest
from ciphermesh.trust.keys import SigningIdentity, TrustStore, load_public_key
from ciphermesh.trust.provision import provision
from ciphermesh.trust.secure_agent import AgentConfig, SecureCipherMeshAgent
from ciphermesh.trust.verifier import CommandVerifier, FailureLimiter

from .helpers import PASS


@pytest.fixture(scope="session")
def prov(tmp_path_factory):
    base = tmp_path_factory.mktemp("trust")
    return provision(base / "trust", base / "keys", passphrase=PASS)


@pytest.fixture
def store(prov):
    """A fresh copy of the provisioned trust store (tests may mutate it)."""
    return TrustStore.load(prov.trust_path)


@pytest.fixture
def ids(prov):
    return prov.identities


@pytest.fixture
def attacker():
    return SigningIdentity.generate("rogue-console-99")


@pytest.fixture
def verifier(store):
    return CommandVerifier(store, limiter=FailureLimiter(threshold=1000))


@pytest.fixture
def make_agent(prov, tmp_path):
    def _make(code_root=None, config=None, audit=True):
        store = TrustStore.load(prov.trust_path)
        return SecureCipherMeshAgent(prov.identities[store.agent_id], store,
                                     signed_manifest=load_signed_manifest(prov.manifest_path),
                                     release_public_key=load_public_key(prov.release_pub_path),
                                     code_root=code_root, trust_store_path=prov.trust_path,
                                     audit_log_path=(tmp_path / "events.jsonl") if audit else None,
                                     config=config or AgentConfig(lockout_threshold=1000))
    return _make
