"""GET /info (api-surface.md §2.1): version and supported contract-version
range. `contract_version` here is the REST API's own contract range
(ADR-0004, "OpenAPI schema as the contract") — a distinct thing from the SDK
contract's manifest-declared `contract` range (sdk-contract-v1.md §2.1),
which has no handshake endpoint of its own.
"""

from importlib.metadata import version

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

SUPPORTED_CONTRACT_RANGE = ">=1.0,<2.0"


class InfoResponse(BaseModel):
    version: str
    contract_version: str


@router.get("/info")
def info() -> InfoResponse:
    return InfoResponse(
        version=version("gameframework-backend"),
        contract_version=SUPPORTED_CONTRACT_RANGE,
    )
