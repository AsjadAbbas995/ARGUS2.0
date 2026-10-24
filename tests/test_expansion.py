"""Discovery-to-task expansion tests (Phase 20A).

``recon.expansion.plan_discovery_expansion`` is a pure function turning one
completed discovery task's artifacts into scope-checked child tasks. No I/O, no
tools, no database -- the served wiring persists the children afterwards
(``api/serve._enqueue_expansion``), so this module only needs to prove the
*mapping*: what an artifact implies, when it is proposed, and how the result is
bounded, allowlisted, deduplicated and deterministic.
"""

from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest

from core.scope_guard import ScopeConfig, ScopeGuard
from database.models.entities import Task
from recon.dns.resolver import IpObservation
from recon.historical import HistoricalUrlObservation
from recon.expansion import (
    CHILD_TYPE_CONTENT_DISCOVER,
    CHILD_TYPE_DNS,
    CHILD_TYPE_HTTP_PROBE,
    CHILD_TYPE_JS_ANALYSIS,
    CHILD_TYPE_PORT_SCAN,
    CHILD_TYPE_TECH_DETECT,
    CHILD_TYPE_WEB_CRAWL,
    plan_discovery_expansion,
)
from recon.ports.nmap import PortObservation
from recon.web.httpx_probe import WebAppObservation
from recon.web.katana import (
    EndpointObservation,
    JavascriptFileObservation,
    ParameterObservation,
    UrlObservation,
)


def _scope() -> ScopeGuard:
    return ScopeGuard.from_config(
        ScopeConfig(
            allowed_domains=("example.com",),
            allowed_ips=("203.0.113.0/24",),
            excluded=("internal.example.com",),
        )
    )


def _parent(*, target: str = "example.com", task_type: str = "subfinder") -> Task:
    return Task(id=uuid4(), run_id=uuid4(), type=task_type, target=target)


def _expand(artifacts, *, parent=None, available_types=None, **kwargs):
    return plan_discovery_expansion(
        artifacts,
        parent=parent or _parent(),
        scope=_scope(),
        available_types=available_types
        or ("dns_resolve", "port_scan", "http_probe"),
        **kwargs,
    )


def _types(tasks) -> set[str]:
    return {t.type for t in tasks}


def _targets(tasks, child_type: str) -> list[str]:
    return sorted(t.target for t in tasks if t.type == child_type)


TYPES_WITH_TECH = ("dns_resolve", "port_scan", "http_probe", "tech_detect")


def _web_app(
    *,
    host: str = "www.example.com",
    port: int = 443,
    title: str = "",
    webserver: str = "",
    content_type: str = "",
) -> WebAppObservation:
    return WebAppObservation(
        host=host,
        url=f"https://{host}:{port}/",
        scheme="https",
        port=port,
        status_code=200,
        title=title,
        webserver=webserver,
        content_type=content_type,
    )


# -- mapping ------------------------------------------------------------------


def test_subdomain_string_implies_dns_resolution() -> None:
    tasks = _expand(["www.example.com", "api.example.com"])
    assert _types(tasks) == {"dns_resolve"}
    assert _targets(tasks, CHILD_TYPE_DNS) == ["api.example.com", "www.example.com"]


def test_resolved_ip_implies_port_scan_of_the_parent_host() -> None:
    parent = _parent(target="www.example.com", task_type="dns_resolve")
    tasks = _expand(
        [IpObservation(address="203.0.113.10", record_type="A")],
        parent=parent,
        ancestor_type="subfinder",
    )
    assert _types(tasks) == {"port_scan"}
    assert _targets(tasks, CHILD_TYPE_PORT_SCAN) == ["www.example.com"]


def test_root_dns_resolve_never_injects_a_port_scan() -> None:
    # Phase 14 contract: a user-enqueued root ``dns_resolve`` must execute exactly
    # the tasks that were planned. Its resolved IP is evidence, not a mandate to
    # scan -- only a discovery-chain continuation deepens into ``port_scan``.
    parent = _parent(target="www.example.com", task_type="dns_resolve")
    assert (
        _expand(
            [IpObservation(address="203.0.113.10", record_type="A")], parent=parent
        )
        == []
    )


def test_subdomain_enum_ancestor_also_allows_port_scan() -> None:
    # ``subdomain_enum`` is an alias of ``subfinder``; both seed the chain.
    parent = _parent(target="www.example.com", task_type="dns_resolve")
    tasks = _expand(
        [IpObservation(address="203.0.113.10", record_type="A")],
        parent=parent,
        ancestor_type="subdomain_enum",
    )
    assert _targets(tasks, CHILD_TYPE_PORT_SCAN) == ["www.example.com"]


def test_open_web_port_implies_http_probe_of_host_port() -> None:
    parent = _parent(target="www.example.com", task_type="port_scan")
    tasks = _expand(
        [
            PortObservation(
                address="203.0.113.10",
                port=443,
                state="open",
                service="https",
                host="www.example.com",
            )
        ],
        parent=parent,
    )
    assert _types(tasks) == {"http_probe"}
    assert _targets(tasks, CHILD_TYPE_HTTP_PROBE) == ["www.example.com:443"]


def test_http_probe_falls_back_to_parent_host_when_host_is_empty() -> None:
    parent = _parent(target="www.example.com", task_type="port_scan")
    tasks = _expand(
        [PortObservation(address="203.0.113.10", port=80, state="open")],
        parent=parent,
    )
    assert _targets(tasks, CHILD_TYPE_HTTP_PROBE) == ["www.example.com:80"]


# -- safety -------------------------------------------------------------------


def test_out_of_scope_subdomain_is_never_proposed() -> None:
    tasks = _expand(["attacker-controlled.example.net"])
    assert tasks == []


def test_excluded_subdomain_is_never_proposed() -> None:
    tasks = _expand(["internal.example.com"])
    assert tasks == []


def test_resolved_out_of_scope_ip_is_never_proposed() -> None:
    parent = _parent(target="www.example.com", task_type="dns_resolve")
    tasks = _expand(
        [IpObservation(address="198.51.100.5", record_type="A")],
        parent=parent,
        ancestor_type="subfinder",
    )
    assert tasks == []


def test_non_web_or_closed_ports_are_never_proposed() -> None:
    parent = _parent(target="www.example.com", task_type="port_scan")
    tasks = _expand(
        [
            PortObservation(address="203.0.113.10", port=22, state="open"),
            PortObservation(address="203.0.113.10", port=443, state="closed"),
            PortObservation(address="203.0.113.10", port=443, state="filtered"),
        ],
        parent=parent,
    )
    assert tasks == []


def test_nothing_is_proposed_without_a_scope() -> None:
    tasks = plan_discovery_expansion(
        ["www.example.com"],
        parent=_parent(),
        scope=None,
        available_types=("dns_resolve", "port_scan", "http_probe"),
    )
    assert tasks == []


def test_allowlist_blocks_unregistered_types() -> None:
    tasks = _expand(["www.example.com"], available_types=("port_scan",))
    assert tasks == []


# -- structure / determinism --------------------------------------------------


def test_children_carry_provenance_and_fingerprint() -> None:
    parent = _parent(target="example.com")
    tasks = _expand(["www.example.com"], parent=parent)
    assert len(tasks) == 1
    child = tasks[0]
    assert child.run_id == parent.run_id
    assert child.parent_task_id == parent.id
    assert child.fingerprint
    assert child.status == "pending"


def test_same_artifacts_are_deduplicated_and_deterministic() -> None:
    artifacts = ["www.example.com", "www.example.com", "api.example.com"]
    first = _expand(artifacts)
    second = _expand(artifacts)
    assert [t.target for t in first] == [t.target for t in second]
    assert len([t for t in first if t.type == CHILD_TYPE_DNS]) == 2


def test_max_tasks_bounds_the_output() -> None:
    hosts = [f"h{i}.example.com" for i in range(10)]
    tasks = _expand(hosts, max_tasks=3)
    assert len(tasks) == 3
    # Deterministic frontier: the same artifacts always propose the same three.
    again = _expand(hosts, max_tasks=3)
    assert [t.target for t in tasks] == [t.target for t in again]


def test_children_tasks_are_plain_tasks() -> None:
    tasks = _expand(["www.example.com"])
    assert all(isinstance(t, Task) for t in tasks)
    assert all(t.id for t in tasks)


# -- mapping: web app -> tech_detect (Phase 21A) ------------------------------


def test_web_app_observation_implies_tech_detect() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(webserver="nginx", title="Example", content_type="text/html")],
        parent=parent,
        available_types=TYPES_WITH_TECH,
    )
    assert _types(tasks) == {"tech_detect"}
    assert _targets(tasks, CHILD_TYPE_TECH_DETECT) == ["www.example.com:443"]


def test_tech_detect_child_embeds_captured_signals_for_fingerprint_reuse() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [
            _web_app(
                webserver=" cloudflare ",
                title="Example App",
                content_type="text/html; charset=utf-8",
            )
        ],
        parent=parent,
        available_types=TYPES_WITH_TECH,
    )
    assert len(tasks) == 1
    assert json.loads(tasks[0].reason) == {
        "server_header": "cloudflare",
        "title": "Example App",
        "content_type": "text/html; charset=utf-8",
    }


def test_tech_detect_child_fetches_when_the_probe_captured_no_signals() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app()],
        parent=parent,
        available_types=TYPES_WITH_TECH,
    )
    assert len(tasks) == 1
    assert tasks[0].reason is None


def test_tech_detect_is_blocked_when_not_allowlisted() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(webserver="nginx")],
        parent=parent,
    )
    assert tasks == []


def test_tech_detect_never_targets_an_out_of_scope_host() -> None:
    parent = _parent(target="example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(host="evil.example.org")],
        parent=parent,
        available_types=TYPES_WITH_TECH,
    )
    assert tasks == []


def test_tech_detect_never_targets_a_non_web_port() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=22)],
        parent=parent,
        available_types=TYPES_WITH_TECH,
    )
    assert tasks == []


def test_duplicate_web_apps_propose_one_tech_detect_task() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(webserver="nginx"), _web_app(webserver="nginx")],
        parent=parent,
        available_types=TYPES_WITH_TECH,
    )
    assert len(tasks) == 1
    assert _types(tasks) == {"tech_detect"}

    dedup = _expand(
        [_web_app(webserver="nginx"), _web_app(webserver="apache")],
        parent=parent,
        available_types=TYPES_WITH_TECH,
    )
    assert [t.target for t in dedup] == ["www.example.com:443"]


# -- mapping: web app -> web_crawl / katana (Phase 22) -------------------------


TYPES_WITH_CRAWL = TYPES_WITH_TECH + ("web_crawl",)


def test_web_app_observation_implies_web_crawl() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
    )
    assert _types(tasks) == {"tech_detect", "web_crawl"}
    assert _targets(tasks, CHILD_TYPE_WEB_CRAWL) == ["https://www.example.com:443/"]


def test_crawl_target_uses_the_recorded_app_url() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [WebAppObservation(host="www.example.com", url="https://www.example.com/", scheme="https", port=443, status_code=200)],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
    )
    assert _targets(tasks, CHILD_TYPE_WEB_CRAWL) == ["https://www.example.com/"]


def test_crawl_seed_falls_back_to_scheme_host_port() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    for port, scheme in ((80, "http"), (443, "https"), (8443, "https"), (8080, "http")):
        tasks = _expand(
            [
                WebAppObservation(
                    host="www.example.com",
                    url="",
                    scheme=scheme,
                    port=port,
                    status_code=200,
                )
            ],
            parent=parent,
            available_types=TYPES_WITH_CRAWL,
        )
        assert _targets(tasks, CHILD_TYPE_WEB_CRAWL) == [
            f"{scheme}://www.example.com:{port}/"
        ]


def test_crawl_reason_carries_the_seed_url_for_reuse() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=8080)],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
    )
    crawler = next(t for t in tasks if t.type == CHILD_TYPE_WEB_CRAWL)
    assert json.loads(crawler.reason or "{}") == {"url": crawler.target}


def test_katana_spelling_proposes_one_katana_task() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_TECH + ("katana",),
    )
    assert _types(tasks) == {"tech_detect", "katana"}
    assert _targets(tasks, "katana") == ["https://www.example.com:443/"]


def test_web_crawl_and_katana_never_both_propose_a_crawler() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_TECH + ("web_crawl", "katana"),
    )
    crawlers = [t for t in tasks if t.type in ("web_crawl", "katana")]
    assert len(crawlers) == 1
    assert crawlers[0].type == "web_crawl"


def test_crawl_is_blocked_when_no_crawl_type_is_allowlisted() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(webserver="nginx")],
        parent=parent,
        available_types=TYPES_WITH_TECH,
    )
    assert _types(tasks) == {"tech_detect"}


def test_crawl_honors_the_crawling_config_gate() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    off = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
        config={"web": {"crawling": False}},
    )
    assert _types(off) == {"tech_detect"}
    default = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
    )
    assert "web_crawl" in _types(default)
    explicit_on = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
        config={"web": {"crawling": True}},
    )
    assert "web_crawl" in _types(explicit_on)


def test_crawl_never_targets_an_out_of_scope_host() -> None:
    parent = _parent(target="example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(host="evil.example.org", port=443)],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
    )
    assert tasks == []


def test_crawl_never_proposed_for_a_non_web_port() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [
            WebAppObservation(
                host="www.example.com",
                url="http://www.example.com:2222/",
                scheme="http",
                port=2222,
                status_code=200,
            )
        ],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
    )
    assert tasks == []


def test_duplicate_web_apps_propose_one_crawl_task() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443), _web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
    )
    assert len([t for t in tasks if t.type == CHILD_TYPE_WEB_CRAWL]) == 1


# -- mapping: web app -> content_discover / ffuf (Phase 23) ---------------------


TYPES_WITH_DISCOVER = TYPES_WITH_CRAWL + ("content_discover",)

_APPROVED_DISCOVERY_CONFIG = {
    "web": {"content_discovery": {"enabled": True, "wordlist": "/tmp/words.txt"}}
}


def test_web_app_observation_with_approved_wordlist_implies_content_discover() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_DISCOVER,
        config=_APPROVED_DISCOVERY_CONFIG,
    )
    assert _types(tasks) == {"tech_detect", "web_crawl", "content_discover"}
    assert _targets(tasks, CHILD_TYPE_CONTENT_DISCOVER) == ["https://www.example.com:443/"]


def test_content_discover_target_uses_the_recorded_app_url() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [
            WebAppObservation(
                host="www.example.com",
                url="https://www.example.com/",
                scheme="https",
                port=443,
                status_code=200,
            )
        ],
        parent=parent,
        available_types=TYPES_WITH_DISCOVER,
        config=_APPROVED_DISCOVERY_CONFIG,
    )
    assert _targets(tasks, CHILD_TYPE_CONTENT_DISCOVER) == ["https://www.example.com/"]


def test_content_discover_reason_carries_the_seed_url_for_reuse() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=8080)],
        parent=parent,
        available_types=TYPES_WITH_DISCOVER,
        config=_APPROVED_DISCOVERY_CONFIG,
    )
    discoverer = next(t for t in tasks if t.type == CHILD_TYPE_CONTENT_DISCOVER)
    assert json.loads(discoverer.reason or "{}") == {"url": discoverer.target}


def test_ffuf_spelling_proposes_one_ffuf_task() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_TECH + ("ffuf",),
        config=_APPROVED_DISCOVERY_CONFIG,
    )
    assert _types(tasks) == {"tech_detect", "ffuf"}
    assert _targets(tasks, "ffuf") == ["https://www.example.com:443/"]


def test_content_discover_and_ffuf_never_both_propose() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_TECH + ("content_discover", "ffuf"),
        config=_APPROVED_DISCOVERY_CONFIG,
    )
    discoverers = [t for t in tasks if t.type in ("content_discover", "ffuf")]
    assert len(discoverers) == 1
    assert discoverers[0].type == "content_discover"


def test_content_discover_requires_an_approved_wordlist() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    # The plain boolean gate is *enabled but unapproved*: no wordlist -> the child
    # is never proposed, because the FFUF adapter is fail-closed without one.
    no_config = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_DISCOVER,
    )
    assert "content_discover" not in _types(no_config)
    enabled_only = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_DISCOVER,
        config={"web": {"content_discovery": True}},
    )
    assert _types(enabled_only) == {"tech_detect", "web_crawl"}


def test_content_discover_honors_the_disabled_mapping_gate() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_DISCOVER,
        config={
            "web": {
                "content_discovery": {"enabled": False, "wordlist": "/tmp/words.txt"}
            }
        },
    )
    assert "content_discover" not in _types(tasks)


def test_content_discover_is_blocked_when_not_allowlisted() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_CRAWL,
        config=_APPROVED_DISCOVERY_CONFIG,
    )
    assert _types(tasks) == {"tech_detect", "web_crawl"}


def test_duplicate_web_apps_propose_one_content_discover_task() -> None:
    parent = _parent(target="www.example.com", task_type="http_probe")
    tasks = _expand(
        [_web_app(port=443), _web_app(port=443)],
        parent=parent,
        available_types=TYPES_WITH_DISCOVER,
        config=_APPROVED_DISCOVERY_CONFIG,
    )
    assert len([t for t in tasks if t.type == CHILD_TYPE_CONTENT_DISCOVER]) == 1


# -- mapping: historical URL is passive, never expanded (Phase 24) ---------------


def test_historical_url_observation_never_proposes_a_probe() -> None:
    # A passively discovered historical URL must not cause active probing of a host
    # that may no longer exist. ``plan_discovery_expansion`` has no branch for
    # ``HistoricalUrlObservation``, so it is inert -- this is the acceptance guard.
    parent = _parent(target="example.com", task_type="historical_recon")
    tasks = _expand(
        [
            HistoricalUrlObservation(
                host="www.example.com",
                port=443,
                path="/old/admin",
                url="https://www.example.com/old/admin",
                source="gau",
            )
        ],
        parent=parent,
        available_types=TYPES_WITH_TECH
        + ("web_crawl", "katana", "content_discover", "ffuf", "historical_recon", "gau"),
    )
    assert tasks == []
    assert "http_probe" not in _types(tasks)


def test_historical_run_expands_to_nothing_even_when_all_children_allowed() -> None:
    parent = _parent(target="example.com", task_type="historical_recon")
    tasks = _expand(
        [
            HistoricalUrlObservation(
                host="api.example.com",
                port=8080,
                path="/v1/legacy",
                url="http://api.example.com:8080/v1/legacy",
                source="gau",
            )
        ],
        parent=parent,
        available_types=(
            "dns_resolve",
            "port_scan",
            "http_probe",
            "tech_detect",
            "web_crawl",
            "katana",
            "content_discover",
            "ffuf",
            "historical_recon",
            "gau",
        ),
    )
    assert _types(tasks) == set()


# -- mapping: JavaScript file -> js_analysis (Phase 25) -------------------------


TYPES_WITH_JS = TYPES_WITH_TECH + ("js_analysis",)


def _js_file(
    *,
    host: str = "www.example.com",
    port: int = 443,
    url: str = "https://www.example.com/app.js",
) -> JavascriptFileObservation:
    return JavascriptFileObservation(host=host, port=port, url=url)


def test_js_file_observation_implies_one_js_analysis_task() -> None:
    parent = _parent(target="www.example.com", task_type="web_crawl")
    tasks = _expand(
        [_js_file()],
        parent=parent,
        available_types=TYPES_WITH_JS,
    )
    assert _types(tasks) == {CHILD_TYPE_JS_ANALYSIS}
    child = next(t for t in tasks if t.type == CHILD_TYPE_JS_ANALYSIS)
    assert child.target == "https://www.example.com/app.js"
    assert child.run_id == parent.run_id
    assert child.parent_task_id == parent.id


def test_js_analysis_is_blocked_when_not_allowlisted() -> None:
    # Disabled gate -> the type is absent from ``available_types`` -> no task.
    tasks = _expand([_js_file()], available_types=TYPES_WITH_TECH)
    assert CHILD_TYPE_JS_ANALYSIS not in _types(tasks)
    assert tasks == []


def test_duplicate_js_urls_propose_one_task() -> None:
    tasks = _expand(
        [_js_file(), _js_file()],
        available_types=TYPES_WITH_JS,
    )
    assert len([t for t in tasks if t.type == CHILD_TYPE_JS_ANALYSIS]) == 1


def test_out_of_scope_js_host_is_never_proposed() -> None:
    tasks = _expand(
        [_js_file(host="evil.example.org", url="https://evil.example.org/app.js")],
        available_types=TYPES_WITH_JS,
    )
    assert tasks == []


def test_distinct_js_urls_propose_distinct_tasks() -> None:
    tasks = _expand(
        [
            _js_file(url="https://www.example.com/a.js"),
            _js_file(url="https://www.example.com/b.js"),
        ],
        available_types=TYPES_WITH_JS,
    )
    assert _targets(tasks, CHILD_TYPE_JS_ANALYSIS) == [
        "https://www.example.com/a.js",
        "https://www.example.com/b.js",
    ]


def test_analyzer_output_observations_never_expand() -> None:
    # No-probe / no-recursion guarantee: the analyzer emits only URL/endpoint/
    # parameter observations, and none of them has an expansion branch, even when
    # every task type -- including js_analysis itself -- is allowlisted.
    all_types = TYPES_WITH_JS + (
        "web_crawl",
        "katana",
        "content_discover",
        "ffuf",
        "historical_recon",
        "gau",
    )
    tasks = _expand(
        [
            UrlObservation(host="www.example.com", port=443, path="/api/users"),
            EndpointObservation(
                host="www.example.com", port=443, path="/api/users", method="GET"
            ),
            ParameterObservation(
                host="www.example.com", port=443, path="/api/users", name="id"
            ),
        ],
        parent=_parent(target="https://www.example.com/app.js", task_type="js_analysis"),
        available_types=all_types,
    )
    assert tasks == []
