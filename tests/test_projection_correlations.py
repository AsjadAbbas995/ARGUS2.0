"""Phase 28: populated endpoint/parameter correlation through the read projection.

Synthetic, in-memory ``RunFacts`` only -- no PostgreSQL, no DSN, no network. These gates
prove that ``database.projection.project`` surfaces the Phase 27 helper's grouping from
real projected records, preserves duplicate observations, attaches parameters by exact
identity, normalizes evidence IDs, and serializes the result deterministically.
"""

from __future__ import annotations

import json
from uuid import UUID, uuid4

from correlation.records import EndpointRecord, endpoint_key
from database.projection import RunFacts, project, serialize, unavailable

_USERS_KEY = endpoint_key("GET", "/users/{id}", "example.com")
_LOGIN_KEY = endpoint_key("POST", "/login", "example.com")


def _ordered(values, reverse: bool):
    return tuple(reversed(values)) if reverse else tuple(values)


def _facts(*, reverse: bool = False) -> tuple[RunFacts, dict[str, UUID]]:
    """Build a fully evidenced asset -> IP -> port -> web app -> URL -> endpoint chain."""
    (
        asset_id,
        ip_id,
        port_id,
        app_id,
        users_url_id,
        login_url_id,
        users_ep_a,
        users_ep_b,
        login_ep,
        id_param,
        expand_param,
        password_param,
    ) = (uuid4() for _ in range(12))

    evidence = [
        ("asset", asset_id, "ev-01"),
        ("ip", ip_id, "ev-02"),
        ("port", port_id, "ev-03"),
        ("web_app", app_id, "ev-04"),
        ("url", users_url_id, "ev-05"),
        ("url", login_url_id, "ev-06"),
        # Endpoint and parameter evidence ids are deliberately not in row order.
        ("endpoint", users_ep_a, "ev-12"),
        ("endpoint", users_ep_b, "ev-11"),
        ("endpoint", login_ep, "ev-13"),
        ("parameter", id_param, "ev-22"),
        ("parameter", expand_param, "ev-21"),
        ("parameter", password_param, "ev-23"),
    ]
    rows = [
        {"evidence_id": evidence_id, "entity_type": kind, "entity_id": entity_id}
        for kind, entity_id, evidence_id in evidence
    ]
    rows.sort(key=lambda row: row["evidence_id"])
    base, _ = RunFacts.from_evidence_rows(rows)

    assets = ({"id": asset_id, "hostname": "example.com", "program_id": uuid4()},)
    ips = ({"id": ip_id, "address": "93.184.216.34"},)
    ports = ({"id": port_id, "ip_id": ip_id, "port_number": 443, "service": None},)
    web_apps = (
        {
            "id": app_id,
            "asset_id": asset_id,
            "port_id": port_id,
            "status_code": 200,
            "title": "Example",
        },
    )
    urls = (
        {
            "id": users_url_id,
            "web_app_id": app_id,
            "path": "/users/1",
            "source": "crawl",
            "historical": False,
        },
        {
            "id": login_url_id,
            "web_app_id": app_id,
            "path": "/login",
            "source": "crawl",
            "historical": False,
        },
    )
    endpoints = (
        {
            "id": users_ep_a,
            "url_id": users_url_id,
            "method": "GET",
            "pattern": "/users/{id}",
        },
        {
            "id": users_ep_b,
            "url_id": users_url_id,
            "method": "GET",
            "pattern": "/users/{id}",
        },
        {
            "id": login_ep,
            "url_id": login_url_id,
            "method": "POST",
            "pattern": "/login",
        },
    )
    parameters = (
        {
            "id": id_param,
            "endpoint_id": users_ep_a,
            "name": "id",
            "location": "path",
            "significance": "object_id",
        },
        {
            "id": expand_param,
            "endpoint_id": users_ep_a,
            "name": "expand",
            "location": "query",
            "significance": "low",
        },
        {
            "id": password_param,
            "endpoint_id": login_ep,
            "name": "password",
            "location": "body",
            "significance": "high",
        },
    )
    asset_ips = ({"asset_id": asset_id, "ip_id": ip_id},)

    facts = RunFacts(
        fact_evidence=base.fact_evidence,
        evidence_counts=base.evidence_counts,
        assets=_ordered(assets, reverse),
        ips=_ordered(ips, reverse),
        ports=_ordered(ports, reverse),
        web_apps=_ordered(web_apps, reverse),
        urls=_ordered(urls, reverse),
        endpoints=_ordered(endpoints, reverse),
        parameters=_ordered(parameters, reverse),
        asset_ips=_ordered(asset_ips, reverse),
    )
    return facts, {
        "asset_id": asset_id,
        "ip_id": ip_id,
        "port_id": port_id,
        "app_id": app_id,
        "users_url_id": users_url_id,
        "login_url_id": login_url_id,
        "users_ep_a": users_ep_a,
        "users_ep_b": users_ep_b,
        "login_ep": login_ep,
        "id_param": id_param,
        "expand_param": expand_param,
        "password_param": password_param,
    }


def _groups_by_key(surface):
    return {group.endpoint_key: group for group in surface.endpoint_correlations}


def test_projection_surfaces_populated_correlation_groups():
    surface = project(None, _facts()[0])
    groups = _groups_by_key(surface)

    assert len(surface.endpoint_correlations) == 2
    assert set(groups) == {_USERS_KEY, _LOGIN_KEY}
    assert surface.available is True


def test_duplicate_endpoint_observations_are_preserved():
    surface = project(None, _facts()[0])
    users = _groups_by_key(surface)[_USERS_KEY]

    assert len(users.endpoints) == 2
    assert [endpoint.evidence_id for endpoint in users.endpoints] == ["ev-11", "ev-12"]
    assert all(isinstance(endpoint, EndpointRecord) for endpoint in users.endpoints)
    assert {(endpoint.method, endpoint.pattern, endpoint.host) for endpoint in users.endpoints} == {
        ("GET", "/users/{id}", "example.com")
    }
    assert len([record for record in surface.records if isinstance(record, EndpointRecord)]) == 3


def test_parameters_attach_only_to_their_exact_endpoint():
    surface = project(None, _facts()[0])
    groups = _groups_by_key(surface)

    assert [
        (param.name, param.location, param.significance, param.evidence_id)
        for param in groups[_USERS_KEY].parameters
    ] == [
        ("id", "path", "object_id", "ev-22"),
        ("expand", "query", "low", "ev-21"),
    ]
    assert [
        (param.name, param.location, param.significance, param.evidence_id)
        for param in groups[_LOGIN_KEY].parameters
    ] == [("password", "body", "high", "ev-23")]
    assert all(param.endpoint_key == _USERS_KEY for param in groups[_USERS_KEY].parameters)
    assert all(param.endpoint_key == _LOGIN_KEY for param in groups[_LOGIN_KEY].parameters)


def test_group_evidence_ids_are_sorted_and_deduplicated():
    surface = project(None, _facts()[0])
    groups = _groups_by_key(surface)

    assert groups[_USERS_KEY].evidence_ids == ("ev-11", "ev-12", "ev-21", "ev-22")
    assert groups[_LOGIN_KEY].evidence_ids == ("ev-13", "ev-23")
    for group in surface.endpoint_correlations:
        assert list(group.evidence_ids) == sorted(set(group.evidence_ids))


def test_serialization_preserves_populated_correlation_payload():
    surface = project(None, _facts()[0])
    payload = serialize(surface)
    section = payload["endpoint_correlations"]
    items = {item["endpoint_key"]: item for item in section["items"]}

    assert section["count"] == 2
    assert set(items) == {_USERS_KEY, _LOGIN_KEY}

    users = items[_USERS_KEY]
    assert users["group_id"] == f"ep:{_USERS_KEY}"
    assert (users["host"], users["method"], users["pattern"]) == (
        "example.com",
        "GET",
        "/users/{id}",
    )
    assert users["endpoint_observations"] == [
        {
            "method": "GET",
            "pattern": "/users/{id}",
            "host": "example.com",
            "evidence_id": "ev-11",
        },
        {
            "method": "GET",
            "pattern": "/users/{id}",
            "host": "example.com",
            "evidence_id": "ev-12",
        },
    ]
    assert users["parameter_observations"] == [
        {
            "name": "id",
            "location": "path",
            "significance": "object_id",
            "endpoint_key": _USERS_KEY,
            "evidence_id": "ev-22",
        },
        {
            "name": "expand",
            "location": "query",
            "significance": "low",
            "endpoint_key": _USERS_KEY,
            "evidence_id": "ev-21",
        },
    ]
    assert users["evidence_ids"] == ["ev-11", "ev-12", "ev-21", "ev-22"]
    json.dumps(payload, sort_keys=True)


def test_repeated_projection_and_serialization_are_deterministic():
    facts = _facts()[0]
    assert serialize(project(None, facts)) == serialize(project(None, facts))


def test_reordered_fact_rows_produce_identical_payloads():
    forward = serialize(project(None, _facts()[0]))
    reversed_rows = serialize(project(None, _facts(reverse=True)[0]))
    assert reversed_rows == forward


def test_unavailable_and_populated_payloads_share_correlation_shape():
    populated = serialize(project(None, _facts()[0]))
    empty = unavailable(None)

    assert set(empty) == set(populated)
    assert set(empty["endpoint_correlations"]) == {"count", "items"}
    assert set(populated["endpoint_correlations"]) == {"count", "items"}
    assert empty["endpoint_correlations"] == {"count": 0, "items": []}
