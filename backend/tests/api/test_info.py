"""GET /api/v1/info (api-surface.md §2.1): version plus the supported
contract-version range. This is the REST API's own contract range (ADR-0004,
"OpenAPI schema as the contract") — not the SDK contract, which is
manifest-declared per artifact and has no handshake endpoint
(sdk-contract-v1.md §1).
"""

from importlib.metadata import version

from fastapi.testclient import TestClient

from gameframework.api.info import SUPPORTED_CONTRACT_RANGE


def test_info_returns_version_and_contract_range(client: TestClient) -> None:
    response = client.get("/api/v1/info")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == version("gameframework-backend")
    assert body["contract_version"] == SUPPORTED_CONTRACT_RANGE


def test_info_is_public_no_session_required(client: TestClient) -> None:
    response = client.get("/api/v1/info")
    assert response.status_code == 200
