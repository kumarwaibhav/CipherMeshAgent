"""Shared fixtures for the Assignment 4.2 knowledge tests. Author: Kumar Waibhav Akshat (RA2212704010027)."""
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ciphermesh.knowledge import load_graph
from ciphermesh.knowledge.feeds import Normaliser

FIX = Path(__file__).resolve().parent / "fixtures"
WHATIF = Path(__file__).resolve().parents[2] / "ciphermesh" / "knowledge" / "data" / "whatif_azure_status.xml"
REPLAY_AS_OF = datetime(2026, 2, 27, 13, 0, tzinfo=timezone.utc)


@pytest.fixture
def graph():
    return load_graph()


@pytest.fixture
def norm(graph):
    return Normaliser(graph)


@pytest.fixture
def fix():
    return FIX
