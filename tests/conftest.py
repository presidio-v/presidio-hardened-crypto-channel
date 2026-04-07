"""Shared pytest fixtures."""

import pytest


@pytest.fixture
def alice_bob_names():
    return ["Alice", "Bob"]
