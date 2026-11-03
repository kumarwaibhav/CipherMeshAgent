"""Shared fixtures for the BDI tests. Author: Kumar Waibhav Akshat (RA2212704010027)."""
import pytest

from ciphermesh.bdi.engine import BDIAgent, CommitmentStrategy
from ciphermesh.bdi.services import EngineServices

CLEAN = "Summarise the main drivers of Q3 cloud spend for the leadership review."
AADHAAR = "Update KYC for the customer with Aadhaar 2345 6789 0124 and email priya.sharma@example.in."
SECRET = "Deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPLE before Friday."
REVIEW = "Why does https://jira.corp.internal/browse/PAY-2291 fail?"


@pytest.fixture
def make_agent():
    def factory(prompt=CLEAN, commitment=CommitmentStrategy.OPEN_MINDED, **kw):
        agent = BDIAgent(EngineServices(), commitment=commitment, **kw)
        agent.perceive_world()
        agent.submit(prompt, "req-test")
        return agent
    return factory
