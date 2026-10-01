"""Phase 15: the canonical read projection, its run scoping, and report integration.

No database and no DSN are required. These gates pin the properties that make the
projection trustworthy, using hand-built rows so each rule can be violated one at a time:

* **run scoping** -- a canonical entity reaches a run's graph only through that run's own
  ``evidence`` row, never through shared program ownership, ``discovered_at`` ordering or
  any other heuristic;
* **containment** -- an association is projected only when both endpoints are themselves
  evidenced in the same run, so a projected edge can never cite a fact the run did not
  observe;
* **withholding over fabrication** -- a record whose graph parents are not evidenced is
  withheld, and no endpoint/parameter/auth/API/JavaScript/certificate record is ever
  created for a producer that does not exist;
* **purity and determinism** -- the same rows always yield the same records, graph and
  inferences;
* **truth separation** -- an inference stays a labelled hypothesis and is never promoted
  into ``validated_findings``, and the report keeps rendering identical output for every
  caller that does not supply an attack surface.

``tests/test_projection_live.py`` proves the same path against real PostgreSQL and
through the served API; nothing here substitutes for that.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.server import create_app
from core.memory_storage import MemoryStorage
from core.orchestrator import Orchestrator
from correlation.records import (
    ApiRecord,
    AuthRecord,
    CertificateRecord,
    DomainRecord,
    EndpointRecord,
    JavaScriptRecord,
    ParameterRecord,
)
from database.models.entities import Run, ToolRun
from database.projection import (
    CANONICAL_ENTITY_TYPES,
    AttackSurface,
    RunFacts,
    build_records,
    project,
    serialize,
    unavailable,
)
from reports import html_report, json_report, markdown_report

_API_KEY = "phase15"
_AUTH = {"Authorization": f"Bearer {_API_KEY}"}

#: Every record type Phase 15 must never emit, because no Phase 14 producer writes one.
_UNPRODUCED = (
    EndpointRecord,
    ParameterRecord,
    AuthRecord,
    ApiRecord,
    JavaScriptRecord,
    CertificateRecord,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _facts(
    *,
    evidence=(),
    assets=(),
    ips=(),
    ports=(),
    web_apps=(),
    technologies=(),
    asset_ips=(),
    asset_technologies=(),
) -> RunFacts:
    """Build ``RunFacts`` from minimal row dicts.

    Evidence rows are given as ``(entity_type, entity_id)`` pairs and sorted by a synthetic
    ascending id here, mirroring the ``ORDER BY e.id`` the repository read issues, so the
    first-wins rule in :meth:`RunFacts.from_evidence_rows` is exercised as written.
    """
    rows = [
        {"evidence_id": f"ev-{index:04d}", "entity_type": kind, "entity_id": entity_id}
        for index, (kind, entity_id) in enumerate(evidence)
    ]
    rows.sort(key=lambda row: row["evidence_id"])
    base, _ = RunFacts.from_evidence_rows(rows)
    return RunFacts(
        fact_evidence=base.fact_evidence,
        evidence_counts=base.evidence_counts,
        assets=tuple(assets),
        ips=tuple(ips),
        ports=tuple(ports),
        web_apps=tuple(web_apps),
        technologies=tuple(technologies),
        asset_ips=tuple(asset_ips),
        asset_technologies=tuple(asset_technologies),
    )


def _chain():
    """Ids and rows for a fully evidenced example.com -> IP -> port -> web app graph."""
    asset_id, ip_id, port_id, app_id, tech_id = (uuid4() for _ in range(5))
    facts = _facts(
        evidence=[
            ("asset", asset_id),
            ("ip", ip_id),
            ("port", port_id),
            ("web_app", app_id),
            ("technology", tech_id),
        ],
        assets=[{"id": asset_id, "hostname": "example.com", "program_id": uuid4()}],
        ips=[{"id": ip_id, "address": "93.184.216.34"}],
        ports=[{"id": port_id, "ip_id": ip_id, "port_number": 443, "service": None}],
        web_apps=[
            {
                "id": app_id,
                "asset_id": asset_id,
                "port_id": port_id,
                "status_code": 200,
                "title": "Example",
            }
        ],
        technologies=[{"id": tech_id, "name": "nginx", "category": "other"}],
        asset_ips=[{"asset_id": asset_id, "ip_id": ip_id}],
        asset_technologies=[{"asset_id": asset_id, "technology_id": tech_id}],
    )
    return facts, {
        "asset_id": asset_id,
        "ip_id": ip_id,
        "port_id": port_id,
        "app_id": app_id,
        "tech_id": tech_id,
    }


# ---------------------------------------------------------------------------
# run scoping: evidence, not ownership or timestamps
# ---------------------------------------------------------------------------


def test_only_evidenced_entities_are_projected():
    """A row that exists but has no evidence for this run is not part of this run."""
    asset_id = uuid4()
    rows = [{"id": asset_id, "hostname": "example.com", "program_id": uuid4()}]
    # The asset row is present and belongs to the run's program, but no evidence names it.
    assert build_records(_facts(assets=rows)) == ()


def test_projection_is_scoped_by_evidence_not_by_row_presence():
    """Two entities in the same program; only the evidenced one appears."""
    evidenced_id, silent_id = uuid4(), uuid4()
    facts = _facts(
        evidence=[("asset", evidenced_id)],
        assets=[
            {"id": evidenced_id, "hostname": "observed.example.com", "program_id": uuid4()},
            {"id": silent_id, "hostname": "unobserved.example.com", "program_id": uuid4()},
        ],
    )
    assert [r.key for r in build_records(facts)] == ["observed.example.com"]


def test_evidence_for_the_same_entity_in_a_later_run_does_not_leak_in():
    """Re-reading a run never picks up facts another run observed."""
    asset_id = uuid4()
    rows = [{"id": asset_id, "hostname": "example.com", "program_id": uuid4()}]
    # The asset exists and another run observed it; this run's evidence set is empty.
    assert build_records(_facts(assets=rows)) == ()
    # The same rows WITH evidence do project.
    assert len(build_records(_facts(evidence=[("asset", asset_id)], assets=rows))) == 1


# ---------------------------------------------------------------------------
# containment: an edge needs both endpoints evidenced
# ---------------------------------------------------------------------------


def test_ip_link_is_not_projected_when_only_the_asset_is_evidenced():
    """Containment: the IP has no evidence for this run, so no ``resolves_to`` edge."""
    asset_id, ip_id = uuid4(), uuid4()
    facts = _facts(
        evidence=[("asset", asset_id)],
        assets=[{"id": asset_id, "hostname": "example.com", "program_id": uuid4()}],
        ips=[{"id": ip_id, "address": "93.184.216.34"}],
        asset_ips=[{"asset_id": asset_id, "ip_id": ip_id}],
    )
    records = build_records(facts)
    assert [r.key for r in records] == ["example.com"], (
        "an edge must never cite an IP this run did not observe"
    )
    surface = project(uuid4(), facts)
    assert surface.graph.edges == ()


def test_ip_link_is_projected_when_both_endpoints_are_evidenced():
    facts, _ids = _chain()
    surface = project(uuid4(), facts)
    resolves = [e for e in surface.graph.edges if e.kind == "resolves_to"]
    assert len(resolves) == 1
    assert resolves[0].source == "example.com"
    assert resolves[0].target == "93.184.216.34"


def test_technology_is_withheld_when_its_asset_is_not_evidenced():
    """A global ``technologies`` row is not a run's fact until a run links it."""
    asset_id, tech_id = uuid4(), uuid4()
    facts = _facts(
        evidence=[("technology", tech_id)],
        assets=[{"id": asset_id, "hostname": "example.com", "program_id": uuid4()}],
        technologies=[{"id": tech_id, "name": "nginx", "category": "other"}],
        asset_technologies=[{"asset_id": asset_id, "technology_id": tech_id}],
    )
    assert build_records(facts) == ()


# ---------------------------------------------------------------------------
# withholding over fabrication
# ---------------------------------------------------------------------------


def test_port_without_an_evidenced_ip_is_withheld_not_reparented():
    """``PortRecord`` needs its IP; without one the port cannot be linked honestly."""
    asset_id, ip_id, port_id = uuid4(), uuid4(), uuid4()
    facts = _facts(
        evidence=[("asset", asset_id), ("port", port_id)],
        assets=[{"id": asset_id, "hostname": "example.com", "program_id": uuid4()}],
        ips=[{"id": ip_id, "address": "93.184.216.34"}],
        ports=[{"id": port_id, "ip_id": ip_id, "port_number": 443}],
    )
    assert [r.key for r in build_records(facts)] == ["example.com"]


def test_web_app_without_an_evidenced_port_is_withheld():
    asset_id, ip_id, port_id, app_id = (uuid4() for _ in range(4))
    facts = _facts(
        evidence=[("asset", asset_id), ("ip", ip_id), ("web_app", app_id)],
        assets=[{"id": asset_id, "hostname": "example.com", "program_id": uuid4()}],
        ips=[{"id": ip_id, "address": "93.184.216.34"}],
        ports=[{"id": port_id, "ip_id": ip_id, "port_number": 443}],
        web_apps=[{"id": app_id, "asset_id": asset_id, "port_id": port_id, "status_code": 200}],
    )
    kinds = {type(r).__name__ for r in build_records(facts)}
    assert "WebAppRecord" not in kinds
    assert "PortRecord" not in kinds


def test_evidenced_ip_with_no_evidenced_owner_is_stored_as_an_orphan_node():
    """Stored unlinked rather than dropped -- 03_RECON_PIPELINE 25's documented behaviour."""
    ip_id = uuid4()
    facts = _facts(
        evidence=[("ip", ip_id)],
        ips=[{"id": ip_id, "address": "203.0.113.7"}],
    )
    surface = project(uuid4(), facts)
    assert [r.key for r in surface.records] == ["203.0.113.7"]
    assert surface.graph.orphan_keys == ("203.0.113.7",)


def test_shared_ip_keeps_a_deterministic_hostname():
    """One ``IpRecord`` per address; the surviving hostname must not depend on row order."""
    first, second, ip_id = uuid4(), uuid4(), uuid4()
    rows = [
        {"id": first, "hostname": "zebra.example.com", "program_id": uuid4()},
        {"id": second, "hostname": "alpha.example.com", "program_id": uuid4()},
    ]
    forwards = _facts(
        evidence=[("asset", first), ("asset", second), ("ip", ip_id)],
        assets=rows,
        ips=[{"id": ip_id, "address": "93.184.216.34"}],
        asset_ips=[{"asset_id": first, "ip_id": ip_id}, {"asset_id": second, "ip_id": ip_id}],
    )
    backwards = _facts(
        evidence=[("asset", first), ("asset", second), ("ip", ip_id)],
        assets=list(reversed(rows)),
        ips=[{"id": ip_id, "address": "93.184.216.34"}],
        asset_ips=[
            {"asset_id": second, "ip_id": ip_id},
            {"asset_id": first, "ip_id": ip_id},
        ],
    )
    assert build_records(forwards) == build_records(backwards)
    ip = next(r for r in build_records(forwards) if r.key == "93.184.216.34")
    assert ip.hostname == "alpha.example.com"


def test_canonical_entity_types_match_the_phase_14_producers_exactly():
    """Pinned against ``recon.ingest`` so a new tag cannot silently stop projecting."""
    from recon.ingest import (
        ENTITY_ASSET,
        ENTITY_ASSET_IP,
        ENTITY_ASSET_TECHNOLOGY,
        ENTITY_DNS_RECORD,
        ENTITY_IP,
        ENTITY_OBSERVED_HOST,
        ENTITY_OBSERVED_IP,
        ENTITY_OBSERVED_WEB_APP,
        ENTITY_PORT,
        ENTITY_TECHNOLOGY,
        ENTITY_WEB_APP,
    )

    assert set(CANONICAL_ENTITY_TYPES) == {
        ENTITY_ASSET,
        ENTITY_DNS_RECORD,
        ENTITY_IP,
        ENTITY_PORT,
        ENTITY_TECHNOLOGY,
        ENTITY_WEB_APP,
    }
    # Tags that are deliberately excluded, and why: the first two are association edges
    # resolved by containment rather than as nodes, the rest name no canonical entity.
    assert {
        ENTITY_ASSET_IP,
        ENTITY_ASSET_TECHNOLOGY,
        ENTITY_OBSERVED_HOST,
        ENTITY_OBSERVED_IP,
        ENTITY_OBSERVED_WEB_APP,
    }.isdisjoint(CANONICAL_ENTITY_TYPES)


def test_no_unproduced_record_type_is_ever_created():
    """No producer exists for these, so the projection must not invent them."""
    facts, _ids = _chain()
    records = build_records(facts)
    for record in records:
        assert not isinstance(record, _UNPRODUCED), (
            f"{type(record).__name__} has no Phase 14 producer"
        )


def test_dns_records_do_not_become_fabricated_graph_nodes():
    """``dns_records`` has a producer but the correlation model has no record for it.

    An address-valued record is already represented by the ``asset_ips`` binding the graph
    turns into ``resolves_to``, so nothing is lost; a CNAME/MX/NS/TXT value has no graph
    representation and must simply not appear.
    """
    asset_id, ip_id = uuid4(), uuid4()
    facts = _facts(
        evidence=[("asset", asset_id), ("ip", ip_id), ("dns_record", uuid4())],
        assets=[{"id": asset_id, "hostname": "example.com", "program_id": uuid4()}],
        ips=[{"id": ip_id, "address": "93.184.216.34"}],
        asset_ips=[{"asset_id": asset_id, "ip_id": ip_id}],
    )
    assert sorted(r.key for r in build_records(facts)) == ["93.184.216.34", "example.com"]


def test_observation_only_evidence_is_counted_but_projects_nothing():
    """A denied observation is reported, never promoted into a node."""
    facts = _facts(
        evidence=[("asset", uuid4()), ("observed_host", None), ("artifact_cap", None)]
    )
    surface = project(uuid4(), facts)
    assert surface.records == ()
    assert surface.evidence_counts == {
        "artifact_cap": 1,
        "asset": 1,
        "observed_host": 1,
    }


# ---------------------------------------------------------------------------
# purity and determinism
# ---------------------------------------------------------------------------


def test_same_rows_always_produce_the_same_records_graph_and_inferences():
    facts, ids = _chain()
    run_id = uuid4()
    first, second = serialize(project(run_id, facts)), serialize(project(run_id, facts))
    assert first == second


def test_input_row_order_does_not_change_the_result():
    """Every read is explicitly ordered, so a differently ordered read is equivalent."""
    facts, _ids = _chain()
    shuffled = RunFacts(
        fact_evidence=facts.fact_evidence,
        evidence_counts=facts.evidence_counts,
        assets=tuple(reversed(facts.assets)),
        ips=tuple(reversed(facts.ips)),
        ports=tuple(reversed(facts.ports)),
        web_apps=tuple(reversed(facts.web_apps)),
        technologies=tuple(reversed(facts.technologies)),
        asset_ips=tuple(reversed(facts.asset_ips)),
        asset_technologies=tuple(reversed(facts.asset_technologies)),
    )
    assert [r.key for r in build_records(facts)] == [r.key for r in build_records(shuffled)]
    run_id = uuid4()
    assert serialize(project(run_id, facts)) == serialize(project(run_id, shuffled))


def test_projection_does_not_mutate_its_input():
    facts, _ids = _chain()
    before = repr(facts)
    project(uuid4(), facts)
    assert repr(facts) == before


# ---------------------------------------------------------------------------
# serialization
# ---------------------------------------------------------------------------


def test_serialized_surface_is_json_safe_and_complete():
    facts, _ids = _chain()
    run_id = uuid4()
    payload = serialize(project(run_id, facts))
    # json.dumps with no default= proves every value is natively serialisable.
    assert json.loads(json.dumps(payload)) == payload
    assert payload["run_id"] == str(run_id)
    assert payload["available"] is True
    assert payload["records"]["count"] == 5
    assert payload["graph"]["node_count"] == 5
    assert payload["graph"]["orphan_count"] == 0
    assert payload["endpoint_subgraph"]["empty"] is True
    assert payload["inferences"]["count"] == 0


def test_every_projected_node_and_edge_carries_its_evidence_id():
    facts, _ids = _chain()
    payload = serialize(project(uuid4(), facts))
    known = {n["evidence_id"] for n in payload["graph"]["nodes"]}
    for node in payload["graph"]["nodes"]:
        assert node["evidence_id"] in known
    for edge in payload["graph"]["edges"]:
        assert edge["evidence_id"]


def test_payload_lists_are_ordered_by_a_stable_key():
    facts, _ids = _chain()
    payload = serialize(project(uuid4(), facts))
    kinds = [n["kind"] for n in payload["graph"]["nodes"]]
    assert kinds == sorted(kinds)
    edges = [(e["source"], e["kind"], e["target"]) for e in payload["graph"]["edges"]]
    assert edges == sorted(edges)


def test_unavailable_matches_the_shape_of_a_real_surface():
    """A consumer must never need to branch on a missing key."""
    payload = unavailable(uuid4())
    assert json.loads(json.dumps(payload)) == payload
    assert payload["available"] is False
    assert payload["run_id"]
    facts, _ids = _chain()
    empty = serialize(project(uuid4(), RunFacts()))
    assert empty["available"] is True, "an observed-nothing run is not the same as no store"
    assert set(empty) == set(payload)


def test_unproduced_record_kinds_are_declared_not_hidden():
    payload = serialize(project(uuid4(), RunFacts()))
    assert "endpoint" in payload["unproduced_record_kinds"]


# ---------------------------------------------------------------------------
# report integration
# ---------------------------------------------------------------------------


def _run() -> Run:
    return Run(program_id=uuid4(), target="example.com")


def _surface() -> dict:
    facts, _ids = _chain()
    return serialize(project(uuid4(), facts))


def test_build_report_omits_the_section_when_no_surface_is_supplied():
    """Backward compatibility: an existing caller's output is byte-for-byte unchanged."""
    report = json_report.build_report(run=_run(), tasks=[])
    assert "attack_surface" not in report
    assert set(report) == {
        "schema_version",
        "generator",
        "run",
        "assets",
        "tasks",
        "tool_runs",
        "evidence_count",
        "dedup",
        "hypotheses",
        "validated_findings",
        "evidence",
    }


def test_json_report_carries_the_surface_verbatim():
    surface = _surface()
    report = json_report.build_report(run=_run(), attack_surface=surface)
    assert report["attack_surface"] == surface
    assert json.loads(json_report.render(report))["attack_surface"] == surface


def test_all_three_formats_render_the_same_surface():
    surface = _surface()
    report = json_report.build_report(run=_run(), attack_surface=surface)
    markdown = markdown_report.render(report)
    html = html_report.render(report)
    # JSON carries the raw numbers; both text projections must state the same ones.
    assert "## Attack Surface" in markdown
    assert "Attack Surface" in html
    for expected in (
        surface["graph"]["node_count"],
        surface["graph"]["edge_count"],
        surface["records"]["count"],
    ):
        assert str(expected) in markdown
        assert str(expected) in html


def test_markdown_and_html_omit_the_section_when_absent():
    report = json_report.build_report(run=_run())
    assert "Attack Surface" not in markdown_report.render(report)
    assert "Attack Surface" not in html_report.render(report)


def test_unavailable_surface_is_rendered_honestly_in_both_text_formats():
    report = json_report.build_report(run=_run(), attack_surface=unavailable(uuid4()))
    markdown = markdown_report.render(report)
    html = html_report.render(report)
    assert "no attack surface was projected" in markdown.lower()
    assert "no attack surface was projected" in html.lower()


def test_inferences_stay_hypotheses_and_are_never_promoted_to_findings():
    """The truth-label contract, enforced on the served report shape."""
    surface = serialize(project(uuid4(), RunFacts()))
    surface["inferences"] = {
        "count": 1,
        "items": [
            {
                "kind": "endpoint_exposure",
                "statement": "possible exposure",
                "target_host": "example.com",
                "evidence_ids": ["ev-0001"],
                "truth_label": "HYPOTHESIS",
            }
        ],
    }
    report = json_report.build_report(run=_run(), attack_surface=surface)
    assert report["validated_findings"] == [], (
        "an inference must never be promoted into a validated finding"
    )
    assert report["hypotheses"] == [], (
        "inferences live in their own labelled section, not the reviewed hypotheses list"
    )
    markdown = markdown_report.render(report)
    assert "**HYPOTHESIS** - possible exposure" in markdown
    assert "hypotheses, not findings" in markdown
    # and the report keeps the two sections separate and ordered
    assert markdown.index("# Facts") < markdown.index("# Hypotheses")
    assert markdown.index("# Hypotheses") < markdown.index("# Validated Findings")


def test_markdown_marks_an_unknown_truth_label_as_unverified():
    surface = serialize(project(uuid4(), RunFacts()))
    surface["inferences"] = {
        "count": 1,
        "items": [{"statement": "s", "truth_label": "TOTALLY_TRUSTED"}],
    }
    markdown = markdown_report.render(
        json_report.build_report(run=_run(), attack_surface=surface)
    )
    assert "**UNVERIFIED_CLAIM** - s" in markdown
    assert "TOTALLY_TRUSTED" not in markdown


def test_html_escapes_inference_text():
    surface = serialize(project(uuid4(), RunFacts()))
    surface["inferences"] = {
        "count": 1,
        "items": [
            {
                "statement": "<script>alert(1)</script>",
                "truth_label": "HYPOTHESIS",
            }
        ],
    }
    html = html_report.render(
        json_report.build_report(run=_run(), attack_surface=surface)
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# API surface, with a storage that has no canonical fact store
# ---------------------------------------------------------------------------


def _client(storage: MemoryStorage) -> TestClient:
    def run_tool(task):
        return ToolRun(task_id=task.id, tool_name=task.type, command=["argus"], exit_code=0)

    app = create_app(
        Orchestrator(storage=storage, run_tool=run_tool), api_key=_API_KEY
    )
    return TestClient(app)


def _seeded_client() -> tuple[TestClient, str]:
    storage = MemoryStorage()
    client = _client(storage)
    created = client.post("/api/v1/runs", json={"target": "example.com"}, headers=_AUTH)
    assert created.status_code == 201, created.text
    return client, created.json()["id"]


def test_attack_surface_route_requires_authentication():
    client, run_id = _seeded_client()
    assert client.get(f"/api/v1/runs/{run_id}/attack-surface").status_code == 401
    assert client.get(f"/api/v1/runs/{run_id}/attack-surface", headers=_AUTH).status_code == 200


def test_attack_surface_route_404s_for_an_unknown_run():
    client, _ = _seeded_client()
    response = client.get(f"/api/v1/runs/{uuid4()}/attack-surface", headers=_AUTH)
    assert response.status_code == 404


def test_attack_surface_route_reports_unavailable_rather_than_an_empty_graph():
    """The payload is the surface itself, keyed like every other run-scoped read."""
    client, run_id = _seeded_client()
    response = client.get(f"/api/v1/runs/{run_id}/attack-surface", headers=_AUTH)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["run_id"] == run_id
    assert payload["available"] is False
    assert payload["records"]["count"] == 0
    assert payload["graph"]["node_count"] == 0
    # The same shape the report embeds, so a consumer can reuse one parser.
    assert set(payload) == set(serialize(AttackSurface(run_id=run_id)))


def test_served_report_still_renders_without_a_canonical_store():
    client, run_id = _seeded_client()
    for fmt in ("json", "markdown", "html"):
        response = client.get(f"/api/v1/runs/{run_id}/reports/{fmt}", headers=_AUTH)
        assert response.status_code == 200, response.text
    body = client.get(f"/api/v1/runs/{run_id}/reports/json", headers=_AUTH).json()
    assert body["attack_surface"]["available"] is False
    assert body["assets"] == {}, (
        "a run with no canonical store must not report asset counts it never measured"
    )
