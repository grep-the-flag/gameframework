"""Host-port allocation for the run preflight (M2-Task-Plan.md Task 13;
data-model.md §3.15/§3.16; sdk-contract-v1.md §4.1).

Split from `services/preflight.py` because the algorithm has two distinct
phases with different write timing: `plan_allocations` is a pure read —
it may run, and raise, before anything about a failing preflight is
written — and `apply_allocations` is the write phase, reached only once
every other check has already passed (data-model.md §3.15: "the first
successful preflight materializes... and allocates").
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.runs import EventRun
from gameframework.db.models.runtime import MinigameInstance, MinigamePort, PortSource


class PortRangeTooSmallError(Exception):
    """sdk-contract-v1.md §4.1 / api-surface.md §2.6: "reporting the range
    size it would need" — not merely refusing. `needed` is the total
    number of live host ports the installation would hold once this run's
    still-missing mappings were allocated (existing occupancy, this run's
    own already-allocated/overridden ports included, plus the missing
    ones); `available` is the configured range's own size.
    """

    def __init__(self, needed: int, available: int) -> None:
        super().__init__(
            f"port range needs at least {needed} ports for this run; "
            f"only {available} are available in the configured range"
        )
        self.needed = needed
        self.available = available


def _live_host_ports(db: Session) -> set[int]:
    """Every host port currently published, installation-wide — a host
    port is unique across the whole installation, not scoped to one run
    (data-model.md §6's partial unique index on
    `minigame_port(host_port) WHERE released_at IS NULL`).
    """
    return set(
        db.execute(select(MinigamePort.host_port).where(MinigamePort.released_at.is_(None)))
        .scalars()
        .all()
    )


def plan_allocations(
    db: Session,
    run: EventRun,
    tcp_ports_by_minigame_id: dict[str, list[int]],
    port_range: tuple[int, int],
) -> list[tuple[str, int]]:
    """The ordered list of `(minigame_id, container_port)` pairs that still
    need a *new* host port for `run` — every declared container port that
    has no `minigame_port` row yet, for a minigame that either has no
    `minigame_instance` row yet (the first preflight) or already does (a
    reconcile). A pair already backed by a row — `allocated` or `override`
    alike — is not in this list; the caller must never touch it (data-
    model.md §3.16, "reconciliation never reassigns an override row").

    Walked in a fixed, deterministic order: minigame id, then container
    port, both ascending (sdk-contract-v1.md §4.1 "deterministically and
    ascending"). No external contract pins this exact order — only that
    the run preflight always resolves the same one for the same inputs —
    so do not "fix" it to a different tie-break; changing it only changes
    which of two equally-valid maps a given installation gets, and a
    reviewer who assumes otherwise will chase a phantom bug.

    Raises `PortRangeTooSmallError`, naming the range size this run would
    need, before anything is written, if the configured range cannot serve
    every still-missing mapping alongside what is already occupied
    installation-wide.
    """
    occupied = _live_host_ports(db)
    range_start, range_end = port_range
    range_size = range_end - range_start + 1

    to_allocate: list[tuple[str, int]] = []
    for minigame_id in sorted(tcp_ports_by_minigame_id):
        instance = db.execute(
            select(MinigameInstance).where(
                MinigameInstance.event_run_id == run.id,
                MinigameInstance.minigame_id == minigame_id,
            )
        ).scalar_one_or_none()
        existing_ports: set[int] = set()
        if instance is not None:
            existing_ports = set(
                db.execute(
                    select(MinigamePort.container_port).where(
                        MinigamePort.minigame_instance_id == instance.id
                    )
                )
                .scalars()
                .all()
            )
        for container_port in sorted(tcp_ports_by_minigame_id[minigame_id]):
            if container_port not in existing_ports:
                to_allocate.append((minigame_id, container_port))

    needed = len(occupied) + len(to_allocate)
    if needed > range_size:
        raise PortRangeTooSmallError(needed=needed, available=range_size)
    return to_allocate


def apply_allocations(
    db: Session,
    instances_by_minigame_id: dict[str, MinigameInstance],
    plan: list[tuple[str, int]],
    port_range: tuple[int, int],
) -> None:
    """Writes one `minigame_port` row per `(minigame_id, container_port)`
    pair in `plan`, in order, each getting the next unoccupied host port
    in `port_range` — ascending, skipping what `plan_allocations` already
    found occupied and what this same call has just taken.
    """
    occupied = _live_host_ports(db)
    range_start, _range_end = port_range
    candidate = range_start
    for minigame_id, container_port in plan:
        while candidate in occupied:
            candidate += 1
        db.add(
            MinigamePort(
                minigame_instance_id=instances_by_minigame_id[minigame_id].id,
                container_port=container_port,
                host_port=candidate,
                source=PortSource.allocated,
            )
        )
        occupied.add(candidate)
        candidate += 1
    db.flush()
