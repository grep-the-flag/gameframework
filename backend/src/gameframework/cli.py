"""The two host commands ADR-0007 "Onboarding, initial password and OTP"
promises (M2-Task-Plan.md Task 5): run inside the backend container via
`docker exec`, never over the API — a host command needs no authentication
of its own because it already requires host access, the same privilege
that could read the database directly.

    python -m gameframework.cli initial-admin-credentials
    python -m gameframework.cli reset-admin <username>
"""

import argparse
import sys
from collections.abc import Sequence

from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.db.session import get_engine
from gameframework.services.bootstrap import credentials_path, reset_admin


def _print_initial_admin_credentials() -> int:
    path = credentials_path(get_settings())
    try:
        sys.stdout.write(path.read_text())
    except FileNotFoundError:
        print(
            f"{path} does not exist. Either the installation has not started "
            "yet, or the admin account has already logged in once — the file "
            "is removed at that account's first successful login "
            "(data-model.md §5).",
            file=sys.stderr,
        )
        return 1
    return 0


def _reset_admin(username: str) -> int:
    settings = get_settings()
    with Session(get_engine()) as db:
        found = reset_admin(db, settings, username)
    if not found:
        print(f"no admin account named {username!r}", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gameframework.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "initial-admin-credentials",
        help="Print the framework-minted initial admin's one-time credentials.",
    )
    reset_parser = subparsers.add_parser(
        "reset-admin",
        help="Reset a named admin account to a fresh random password and clear address blocks.",
    )
    reset_parser.add_argument("username")

    args = parser.parse_args(argv)
    if args.command == "initial-admin-credentials":
        return _print_initial_admin_credentials()
    return _reset_admin(args.username)


if __name__ == "__main__":
    sys.exit(main())
