"""Phase 18: AI coverage gaps - contract tests (no database required)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from ai import run_context
from ai.loop import (
    ANALYSIS_COVERAGE_UNAVAILABLE,
    ANALYSIS_NO_PROPOSALS,
    ANALYSIS_PROPOSED,
    AnalysisHook,
)
@dataclass
class _DummyRun:
    id = uuid4()


class _StorageRecordingGaps:
    def __init__(self):
        self.ai = []
        self.hyps = []
        self.observed = []

    def insert_ai_analysis(self, analysis):
        self.ai.append(analysis)

    def insert_hypothesis(self, hyp):
        self.hyps.append(hyp)

    def transaction(self):
        from contextlib import contextmanager
        @contextmanager
        def cm():
            yield
        return cm

    def attack_surface(self, run_id):
        return {}

    def observe_coverage_gaps(self, run_id, stages):
        self.observed.append((str(run_id), tuple(str(s) for s in stages)))
        return []


class _StorageWithoutGaps(_StorageRecordingGaps):
    def observe_coverage_gaps(self, run_id, stages):
        raise TypeError("no method")


class _StorageFailingGaps(_StorageRecordingGaps):
    def observe_coverage_gaps(self, run_id, stages):
        raise RuntimeError("gap write rejected")


def test_uncovered_without_capability_excludes_runnable():
    tasks = ()
    executable = ("port_scan", "subdomain_enum")
    gaps = run_context.uncovered_without_capability(tasks, executable)
    assert isinstance(gaps, tuple)
    for g in gaps:
        assert g not in executable
def test_hook_records_gaps_when_present():
    run = _DummyRun()
    storage = _StorageRecordingGaps()
    hook = AnalysisHook(storage, executable=["port_scan"], route_config=None, max_hypotheses_per_pass=1)
    tasks = hook(run, [])
    assert tasks == []
    # gaps were observed
    assert storage.observed
    assert storage.observed[0][0] == str(run.id)


def test_hook_surfaces_coverage_unavailable_when_storage_missing():
    run = _DummyRun()
    storage = _StorageWithoutGaps()
    hook = AnalysisHook(storage, executable=[], route_config=None, max_hypotheses_per_pass=1)
    tasks = hook(run, [])
    assert tasks == []
    assert hook.last_result.status == ANALYSIS_COVERAGE_UNAVAILABLE


def test_hook_surfaces_coverage_unavailable_when_write_fails():
    run = _DummyRun()
    storage = _StorageFailingGaps()
    hook = AnalysisHook(storage, executable=[], route_config=None, max_hypotheses_per_pass=1)
    tasks = hook(run, [])
    assert tasks == []
    assert hook.last_result.status == ANALYSIS_COVERAGE_UNAVAILABLE
def test_gaps_never_produced_as_tasks_or_hypotheses():
    run = _DummyRun()
    storage = _StorageRecordingGaps()
    hook = AnalysisHook(storage, executable=[], route_config=None, max_hypotheses_per_pass=1)
    tasks = hook(run, [])
    assert tasks == []
    assert storage.hyps == []
    assert hook.last_result.tasks == ()
