import os

# Keep destructive test fixtures away from the operator's lab database.
os.environ["CCC_DATABASE_URL"] = "sqlite:///./data/cyber_command_center_test.sqlite3"

import pytest

from backend.core.config import get_settings
from backend.core.security import reset_rate_limiter


@pytest.fixture(autouse=True)
def isolated_test_environment(monkeypatch):
    monkeypatch.setenv("CCC_AUTH_ENABLED", "false")
    monkeypatch.delenv("CCC_API_TOKEN", raising=False)
    monkeypatch.setattr("backend.core.config._load_dotenv", lambda path=None: None)
    get_settings.cache_clear()
    reset_rate_limiter()
    yield
    get_settings.cache_clear()
    reset_rate_limiter()
