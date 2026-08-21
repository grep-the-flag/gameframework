"""Cookie sessions (ADR-0007 "Session model") and the cookie shapes
api-surface.md §2.2 names. `current_session` — the eight-position pipeline
the task plan calls load-bearing — lives in `api/deps.py`, where FastAPI's
`Request`/`Response` are available; this module holds the parts that do
not need them: minting, decoding, and sliding renewal.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from sqlalchemy.orm import Session as DbSession

from gameframework.config import Settings
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.models.identity import User
from gameframework.services.secrets import csrf_key, ensure_signing_key

SESSION_COOKIE_NAME = "__Secure-gf_session"
PRESESSION_COOKIE_NAME = "__Host-gf_presession"
_ALGORITHM = "HS256"
SESSION_TTL = timedelta(hours=12)
RENEWAL_THRESHOLD = timedelta(hours=2)
CSRF_TOKEN_TTL = timedelta(hours=2)


@dataclass
class AuthContext:
    user: User
    session: SessionModel


class InvalidSessionToken(Exception):
    """The cookie's JWT failed signature or `exp` verification."""


class InvalidCsrfToken(Exception):
    """The CSRF token failed signature, `exp` or binding verification."""


def cookie_domain(settings: Settings) -> str:
    """The `Domain` attribute's wire form is the framework's to decide, not
    the operator's formatting: `Settings.cookie_domain` carries the bare
    domain, a leading dot is stripped if the operator typed one anyway,
    and exactly one is emitted. RFC 6265 treats a leading dot as
    insignificant, but the `Set-Cookie` header text is compared as
    characters — by browsers and by this codebase's own tests — so the
    form has to be decided once here rather than left to whoever fills in
    `.env`.
    """
    return "." + settings.cookie_domain.lstrip(".")


def _claims(user: User, session_row: SessionModel, expires_at: datetime) -> dict[str, object]:
    return {
        "sub": str(user.id),
        "role": user.role.value,
        "sid": str(session_row.id),
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int(expires_at.timestamp()),
    }


def issue_session(db: DbSession, user: User, settings: Settings) -> tuple[str, SessionModel]:
    """A fresh `sid` row and its JWT — the five ADR-0007 claims, `restricted`
    derived from `must_change_password` (ADR-0007, Session model).
    """
    expires_at = datetime.now(UTC) + SESSION_TTL
    session_row = SessionModel(
        id=uuid.uuid4(),
        user_id=user.id,
        restricted=user.must_change_password,
        expires_at=expires_at,
    )
    db.add(session_row)
    db.commit()
    key = ensure_signing_key(settings)
    # PyJWT's own stubs leave `key` partially untyped (Unknown | PyJWK |
    # str | bytes) — an upstream gap, not ours.
    token = jwt.encode(  # pyright: ignore[reportUnknownMemberType]
        _claims(user, session_row, expires_at), key, algorithm=_ALGORITHM
    )
    return token, session_row


def renew_token(user: User, session_row: SessionModel, settings: Settings) -> str:
    """Sliding renewal (ADR-0007): the same `sid`, a fresh `exp`. Updates
    `session_row.expires_at` to match — the caller commits.
    """
    expires_at = datetime.now(UTC) + SESSION_TTL
    session_row.expires_at = expires_at
    key = ensure_signing_key(settings)
    return jwt.encode(  # pyright: ignore[reportUnknownMemberType]
        _claims(user, session_row, expires_at), key, algorithm=_ALGORITHM
    )


def decode_token(token: str, settings: Settings) -> dict[str, object]:
    key = ensure_signing_key(settings)
    try:
        return jwt.decode(  # pyright: ignore[reportUnknownMemberType]
            token, key, algorithms=[_ALGORITHM]
        )
    except jwt.InvalidTokenError as exc:
        raise InvalidSessionToken from exc


def mint_csrf_token(binding: str, expires_at: datetime, settings: Settings) -> str:
    """A keyed MAC over `binding` — a session's `sid`, or the pre-session
    id riding the `__Host-` cookie before login — and the token's own
    expiry, under `csrf_key()` (ADR-0007 "Session model" — CSRF). The
    expiry is a parameter rather than computed here: the route chooses
    `now + 2h`, this primitive stays clock-free.
    """
    key = csrf_key(ensure_signing_key(settings))
    claims = {"binding": binding, "exp": int(expires_at.timestamp())}
    return jwt.encode(claims, key, algorithm=_ALGORITHM)  # pyright: ignore[reportUnknownMemberType]


def verify_csrf_token(token: str, binding: str, settings: Settings) -> None:
    """Raises `InvalidCsrfToken` unless `token` is a live HS256 JWT under
    `csrf_key()` bound to exactly this `binding`. `algorithms=["HS256"]`
    is pinned rather than read from the token, as `decode_token` above
    already does for the session cookie (ADR-0007, M2-Task-Plan.md Task 3).
    """
    key = csrf_key(ensure_signing_key(settings))
    try:
        claims = jwt.decode(  # pyright: ignore[reportUnknownMemberType]
            token, key, algorithms=[_ALGORITHM]
        )
    except jwt.InvalidTokenError as exc:
        raise InvalidCsrfToken from exc
    if claims.get("binding") != binding:
        raise InvalidCsrfToken("csrf token is bound to a different session")
