"""Storage contract conformance (no database required).

The Orchestrator is written against exactly one thing: the flat ``Storage``
contract declared in ``core.orchestrator``. These gates assert that *both*
implementations of that contract -- the production PostgreSQL repository facade
(``database.repositories.all.Repositories``) and the in-memory test double
(``core.memory_storage.MemoryStorage``) -- declare every contract operation with
the contract's own parameter names. Neither can silently drift, and neither can
be substituted for the other by accident.

This is a *surface* conformance check: it proves the real repository
implementation is actually wired to the contract the orchestrator consumes. It
does **not** and cannot prove that PostgreSQL accepts the writes. That is what
``tests/test_database_live.py`` does, and it skips without a live database.
Nothing in this module substitutes for it.
"""

from __future__ import annotations

import inspect

import pytest

from core.memory_storage import MemoryStorage
from core.orchestrator import Storage
from database.repositories.all import Repositories

#: The exact operation set the orchestrator is allowed to depend on. Asserted
#: literally so that adding to (or silently dropping from) the contract is a
#: deliberate, visible act.
EXPECTED_CONTRACT = sorted(
    [
        "create_run",
        "get_run",
        "list_runs",
        "set_run_status",
        "set_run_progress",
        "insert_tasks",
        "list_tasks",
        "list_tasks_by_status",
        "set_task_status",
        "insert_tool_run",
        "finalize_tool_run",
        "insert_hypothesis",
        "get_hypothesis",
        "list_hypotheses",
        "set_hypothesis_review",
    ]
)

IMPLEMENTATIONS = [
    ("Repositories", Repositories),
    ("MemoryStorage", MemoryStorage),
]

CONTRACT_METHODS = sorted(
    name
    for name, member in vars(Storage).items()
    if not name.startswith("_") and callable(member)
)

#: Contract operations a storage MAY inherit unimplemented. ``set_run_progress``
#: is the optional Phase-8 loop-progress write: the orchestrator detects an
#: unoverridden stub and keeps loop state process-local, so a storage predating
#: Phase 8 still works (restart-fragile) instead of silently discarding progress.
OPTIONAL_CONTRACT_OPERATIONS = {"set_run_progress"}


def test_contract_surface_is_exactly_the_expected_operations() -> None:
    assert CONTRACT_METHODS == EXPECTED_CONTRACT
    assert len(EXPECTED_CONTRACT) == 15


@pytest.mark.parametrize("label,impl", IMPLEMENTATIONS, ids=[i[0] for i in IMPLEMENTATIONS])
def test_implementation_declares_itself_a_storage(label: str, impl: type) -> None:
    assert issubclass(impl, Storage), f"{label} does not declare Storage conformance"


@pytest.mark.parametrize("label,impl", IMPLEMENTATIONS, ids=[i[0] for i in IMPLEMENTATIONS])
def test_implementation_provides_every_contract_operation(label: str, impl: type) -> None:
    missing = [name for name in CONTRACT_METHODS if not callable(getattr(impl, name, None))]
    assert not missing, f"{label} is missing Storage operations: {missing}"


@pytest.mark.parametrize("label,impl", IMPLEMENTATIONS, ids=[i[0] for i in IMPLEMENTATIONS])
def test_implementation_signatures_match_the_contract(label: str, impl: type) -> None:
    for name in CONTRACT_METHODS:
        contract = list(inspect.signature(getattr(Storage, name)).parameters)
        actual = list(inspect.signature(getattr(impl, name)).parameters)
        assert actual == contract, f"{label}.{name}{tuple(actual)} != Storage.{name}{tuple(contract)}"


@pytest.mark.parametrize("label,impl", IMPLEMENTATIONS, ids=[i[0] for i in IMPLEMENTATIONS])
def test_implementation_actually_overrides_every_optional_operation(label: str, impl: type) -> None:
    """Both shipped storages must *implement* the optional operations, not inherit the stub.

    ``Storage`` declares optional operations as no-ops so a storage predating
    Phase 8 still satisfies the contract, and the orchestrator falls back to
    process-local loop state when it sees an unoverridden stub. That fallback
    would silently hide a real implementation gap in a shipped backend, so these
    two implementations are pinned as genuinely durable.
    """
    inherited = [
        name
        for name in OPTIONAL_CONTRACT_OPERATIONS
        if getattr(impl, name, None) is getattr(Storage, name, None)
    ]
    assert not inherited, (
        f"{label} inherits the no-op stub for {sorted(inherited)}; adaptive-loop progress "
        "would be silently discarded instead of persisted"
    )
