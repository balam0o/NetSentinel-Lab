import pytest
from fastapi.testclient import TestClient
from app.api.main import app
from app.db.session import Base, engine
import pytest

@pytest.fixture(autouse=True)
def disable_auth_by_default(monkeypatch):
    monkeypatch.setenv("NETSENTINEL_API_KEY", "")

@pytest.fixture(scope="function")
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as test_client:
        yield test_client

    Base.metadata.drop_all(bind=engine)