"""Shared pytest fixtures and import path setup."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


import pytest


@pytest.fixture
def project_root() -> Path:
    """The APIShield project root (contains main.py)."""
    return PROJECT_ROOT
