"""The audit writer (data-model.md §3.23). Two obligations fall on the
writer that no schema can express:

- the scope <=> event_run_id pairing is a database CHECK
  (`ck_audit_log_scope_event_run`, already proven in
  tests/db/test_constraints.py) — write_audit does not re-validate it and
  simply lets a violation surface as an IntegrityError;
- an `installation`-scope row must not carry participant personal data in
  `details` — no CHECK can express "this jsonb blob contains no PII", so
  this module refuses the write instead. Refused rather than silently
  redacted: a caller that thinks it wrote one thing should not find a
  different thing persisted.

**What the guard assumes.** `write_audit` assumes every caller identifies a
user in `details` by `user_id`, never by name — the row already carries
`actor_user_id` and `target_id` for that. Under that assumption, a key named
`username`/`display_name`/`email` in an installation-scope row is always a
mistake, staff or participant alike: it is refused unconditionally, not
because the writer knows whose name it is (it is not participant-scope
aware). A future caller must not name a user any other way in
installation-scope `details`.

**What the guard does not catch.** It checks key names only, not content:
`{"detail": "imported alice@example.com"}` passes, because free text in
`detail`/`reason`/similar fields is not inspected for embedded personal
data. That gap is accepted for v1 — the caller carries the rest of the
obligation, i.e. never composing free text that embeds a name or address in
an installation-scope row.
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from gameframework.db.models.feedback import AuditLog, AuditScope

_INSTALLATION_SCOPE_FORBIDDEN_KEYS = frozenset({"username", "display_name", "email"})


class AuditDetailsError(ValueError):
    """Raised when an installation-scope audit row's `details` would carry
    participant personal data (data-model.md §3.23)."""


def write_audit(
    db: Session,
    *,
    actor_user_id: uuid.UUID | None,
    scope: AuditScope,
    event_run_id: uuid.UUID | None,
    action: str,
    target_type: str,
    target_id: uuid.UUID,
    details: dict[str, Any],
) -> AuditLog:
    if scope is AuditScope.installation:
        leaked = _INSTALLATION_SCOPE_FORBIDDEN_KEYS & details.keys()
        if leaked:
            raise AuditDetailsError(
                "installation-scope audit row must not carry participant personal "
                f"data in details; found: {sorted(leaked)}"
            )
    entry = AuditLog(
        actor_user_id=actor_user_id,
        scope=scope,
        event_run_id=event_run_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
    )
    db.add(entry)
    db.commit()
    return entry
