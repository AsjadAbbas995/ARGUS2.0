"""Phase 14.3 LIVE end-to-end: served run -> DNS -> HTTP probe -> PostgreSQL.

Gated on ``ARGUS_TEST_DATABASE_URL`` (see ``tests/conftest.py``). This is the
acceptance proof for Phase 14, exercising the whole chain through the real served
composition -- the FastAPI app, the real orchestrator, the real rate limiter, the
real ``ToolRunner``, real adapters, the real repositories, and real PostgreSQL:

    served run -> dns_resolve -> real DNS/IP artifacts -> ingestion
               -> assets / ips / asset_ips
               -> http_probe  -> real web-app artifact  -> ingestion
               -> web_apps -> evidence provenance

Acceptance criteria, asserted with an independent read-only connection:
``>= 1 assets``, ``>= 1 web_apps``, ``>= 1 evidence`` row, with every evidence row
joined back to the actual ``tool_runs`` row and its ``raw_output_ref``.

CONTROLLED TARGET ONLY
    The target is a ``ThreadingHTTPServer`` the test itself starts on
    ``127.0.0.1`` with an ephemeral port, resolved through the loopback names. No
    public or third-party host is contacted at any point.

ENVIRONMENT-UNVERIFIED (stated, not hidden)
    * The ``httpx`` binary is NOT installed on this machine, so the default
      ``HttpxProbeAdapter`` cannot run. The web-app artifact therefore comes from
      :class:`ControlledHttpProbeAdapter`, a real ``ToolAdapter`` that performs a
      genuine HTTP request through the real ``ToolRunner`` subprocess boundary and
      parses the genuine response into a real ``WebAppObservation``. The httpx
      *binary* path remains unverified.
    * DNS uses the adapter's documented ``resolver_fn`` seam backed by
      ``socket.getaddrinfo``, because dnspython does not consult the Windows hosts
      file and therefore cannot resolve ``localhost``. The resolution is still a
      real local resolver call, not a fixture or a fabricated answer.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from uuid import uuid4

import psycopg
import pytest
from psycopg.rows import dict_row
from starlette.testclient import TestClient

from api.serve import create_serve_app
from core.config import Config
from core.scope_guard import ScopeGuard, extract_host
from core.tool_runner import CommandResult, ToolRunner
from database.models.entities import ScopeRule as ScopeRuleEntity
from database.repositories.all import Repositories
from database.repositories.base import DatabaseConnection
from recon.base import ToolAdapter
from recon.web.httpx_probe import WebAppObservation

LOOPBACK = "127.0.0.1"
HOSTNAME = "localhost"
API_KEY = "phase14-key"


# ---------------------------------------------------------------------------
# the controlled local target
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    """A real HTTP server answering a real GET with a real 200 + headers."""

    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        type(self).hits.append(self.path)
        body = b"<html><head><title>argus-phase14</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def version_string(self) -> str:
        # ``send_response`` emits ``Server: <version_string()>``; overriding it is how a
        # real server reports itself, rather than appending a second Server header.
        return "argus-phase14-controlled"

    def log_message(self, *args) -> None:  # keep pytest output clean
        return


class ControlledTarget:
    def __init__(self) -> None:
        _Handler.hits = []
        self._server = ThreadingHTTPServer((LOOPBACK, 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{HOSTNAME}:{self.port}/probe"

    @property
    def hits(self) -> list[str]:
        return list(_Handler.hits)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def target() -> Iterator[ControlledTarget]:
    server = ControlledTarget()
    try:
        yield server
    finally:
        server.close()


# ---------------------------------------------------------------------------
# a real resolver, through the adapter's documented injection seam
# ---------------------------------------------------------------------------


def _local_resolver(hostname: str, record_type: str):
    """Resolve via the OS resolver (which consults the hosts file).

    dnspython queries DNS servers and never reads the hosts file, so it cannot see
    ``localhost``. This keeps the resolution a genuine local lookup while keeping
    the target controlled.
    """
    if record_type not in ("A", "AAAA"):
        return (), "NOANSWER"
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return (), "NXDOMAIN"
    want = socket.AF_INET if record_type == "A" else socket.AF_INET6
    values = [info[4][0] for info in infos if info[0] == want]
    values = list(dict.fromkeys(values))
    return tuple(values), (None if values else "NOANSWER")


# ---------------------------------------------------------------------------
# a real http_probe adapter (the httpx binary is not installed)
# ---------------------------------------------------------------------------

_PROBE_SCRIPT = r"""
import json, sys, urllib.request
url = sys.argv[1]
with urllib.request.urlopen(url, timeout=10) as r:
    body = r.read().decode("utf-8", "replace")
    title = ""
    low = body.lower()
    if "<title>" in low:
        start = low.index("<title>") + 7
        end = low.index("</title>", start)
        title = body[start:end].strip()
    print(json.dumps({
        "status_code": r.status,
        "title": title,
        "server_header": r.headers.get("Server", ""),
        "url": url,
    }))
"""


class ControlledHttpProbeAdapter(ToolAdapter):
    """A real adapter that really performs an HTTP request via the real ToolRunner.

    Emits a genuine :class:`WebAppObservation` built from the real response, so
    what reaches ingestion is a true observation of the controlled target rather
    than a hand-written fixture.
    """

    name = "controlled_http_probe"
    executables = ()

    def __init__(self) -> None:
        self.invocations: list[list[str]] = []

    def is_available(self) -> bool:
        return Path(sys.executable).is_file()

    def validate(self, task, scope: ScopeGuard) -> None:
        self._require_in_scope(task.target, scope)

    def build_command(self, task, config) -> list[str]:
        command = [sys.executable, "-I", "-c", _PROBE_SCRIPT, task.target]
        self.invocations.append(command)
        return command

    def parse(self, result: CommandResult) -> list[object]:
        for line in reversed(result.stdout.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except ValueError:
                continue
            url = data.get("url", "")
            port = int(url.rsplit(":", 1)[-1].split("/")[0]) if ":" in url else 0
            return [
                WebAppObservation(
                    host=extract_host(url),
                    url=url,
                    scheme=url.split(":", 1)[0] if ":" in url else "http",
                    port=port,
                    status_code=int(data.get("status_code") or 0),
                    title=data.get("title", ""),
                    webserver=data.get("server_header", ""),
                )
            ]
        return []


# ---------------------------------------------------------------------------
# program + served client
# ---------------------------------------------------------------------------


def _make_program(database_url: str) -> str:
    """A real program whose persisted scope authorizes the controlled local target.

    Both rules are required and neither is sufficient alone: ``check_host`` needs
    the domain, and ``check_ip`` denies by default unless an IP/CIDR is allowed --
    which is also what makes a ``web_apps`` row possible at all (``port_id`` is
    NOT NULL and is reached through the IP).
    """
    connection = DatabaseConnection(database_url)
    repositories = Repositories(connection.connect())
    try:
        org = repositories.organizations.upsert(f"argus-phase14-org-{uuid4().hex}")
        program = repositories.programs.upsert(
            org["id"], f"argus-phase14-program-{uuid4().hex}"
        )
        for rule_type, value in (("domain", HOSTNAME), ("ip", LOOPBACK)):
            repositories.scope_rules.upsert(
                ScopeRuleEntity(
                    program_id=program["id"],
                    rule_type=rule_type,
                    value=value,
                    allowed=True,
                )
            )
        return str(program["id"])
    finally:
        connection.close()


def _config(database_url: str, raw_dir: Path) -> Config:
    return Config.from_dict(
        {
            "database": {"url": database_url},
            "scope": {"allowed_domains": [HOSTNAME], "allowed_ips": [LOOPBACK]},
            "storage": {"raw_dir": str(raw_dir)},
        }
    )


@pytest.fixture
def program_id(database_url: str) -> str:
    return _make_program(database_url)


@pytest.fixture
def probes() -> list[ControlledHttpProbeAdapter]:
    return []


@pytest.fixture
def client(database_url: str, target: ControlledTarget, probes, tmp_path: Path):
    def factory() -> ControlledHttpProbeAdapter:
        adapter = ControlledHttpProbeAdapter()
        probes.append(adapter)
        return adapter

    app = create_serve_app(
        api_key=API_KEY,
        database_url=database_url,
        config=_config(database_url, tmp_path / "raw"),
        runner=ToolRunner(raw_dir=tmp_path / "raw"),
        resolver_fn=_local_resolver,
        adapters={"http_probe": factory},
    )
    with TestClient(app) as test_client:
        yield test_client


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {API_KEY}"}


def _create_run(client, program_id: str) -> dict:
    response = client.post(
        "/api/v1/runs",
        json={
            "target": HOSTNAME,
            "program_id": program_id,
            "configuration": {
                "scope": {"allowed_domains": [HOSTNAME], "allowed_ips": [LOOPBACK]}
            },
        },
        headers=_auth(),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _enqueue(client, run_id: str, task_type: str, target: str) -> None:
    response = client.post(
        f"/api/v1/runs/{run_id}/tasks",
        json={"tasks": [{"type": task_type, "target": target}]},
        headers=_auth(),
    )
    assert response.status_code == 201, response.text


# ---------------------------------------------------------------------------
# the acceptance test
# ---------------------------------------------------------------------------


def test_served_run_dns_then_http_probe_persists_graph_and_provenance(
    client, target, probes, database_url, program_id
):
    """The full Phase 14 acceptance chain, verified directly in PostgreSQL."""
    run = _create_run(client, program_id)
    run_id = run["id"]

    # the sequence under test: DNS first, then the HTTP probe, same target
    _enqueue(client, run_id, "dns_resolve", HOSTNAME)
    _enqueue(client, run_id, "http_probe", target.url)

    result = client.post(f"/api/v1/runs/{run_id}/run", json={}, headers=_auth())
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["status"] == "COMPLETED", body
    assert body["tasks"]["by_status"] == {"completed": 2}, body["tasks"]

    # the HTTP probe really ran and really reached the controlled target
    assert len(probes) == 1
    assert probes[0].invocations
    assert target.hits == ["/probe"], f"controlled target was not reached: {target.hits}"

    # ---- verified with an INDEPENDENT read-only connection -----------------
    # Everything is scoped to *this* run's tasks and *this* program, so rows left
    # behind in the shared test database by other tests cannot influence the proof.
    with psycopg.connect(database_url, row_factory=dict_row) as conn:
        conn.execute("SET TRANSACTION READ ONLY")

        tool_runs = conn.execute(
            "SELECT t.id, t.tool_name, t.raw_output_ref, t.exit_code "
            "FROM tool_runs t JOIN tasks k ON k.id = t.task_id "
            "WHERE k.run_id = %s ORDER BY t.tool_name",
            (run_id,),
        ).fetchall()
        tool_run_ids = [t["id"] for t in tool_runs]

        evidence = conn.execute(
            "SELECT id, entity_type, entity_id, tool_run_id, raw_reference "
            "FROM evidence WHERE tool_run_id = ANY(%s) ORDER BY entity_type",
            (tool_run_ids,),
        ).fetchall()

        assets = conn.execute(
            "SELECT id, hostname, source FROM assets WHERE program_id = %s ORDER BY hostname",
            (program_id,),
        ).fetchall()
        asset_ids = [a["id"] for a in assets]

        ips = conn.execute(
            "SELECT DISTINCT i.id, i.address FROM asset_ips ai "
            "JOIN ips i ON i.id = ai.ip_id WHERE ai.asset_id = ANY(%s) ORDER BY i.address",
            (asset_ids,),
        ).fetchall()
        links = conn.execute(
            "SELECT asset_id, ip_id FROM asset_ips WHERE asset_id = ANY(%s)",
            (asset_ids,),
        ).fetchall()
        ports = conn.execute(
            "SELECT DISTINCT p.id, p.ip_id, p.port_number, p.protocol, p.state "
            "FROM ports p JOIN web_apps w ON w.port_id = p.id "
            "WHERE w.asset_id = ANY(%s) ORDER BY p.port_number",
            (asset_ids,),
        ).fetchall()
        web_apps = conn.execute(
            "SELECT id, asset_id, port_id, status_code, title, server_header "
            "FROM web_apps WHERE asset_id = ANY(%s)",
            (asset_ids,),
        ).fetchall()

        # ACCEPTANCE CRITERIA
        assert len(assets) >= 1, "expected >= 1 assets row"
        assert len(web_apps) >= 1, "expected >= 1 web_apps row"
        assert len(evidence) >= 1, "expected >= 1 evidence row"

        # the chain really is assets -> ips -> asset_ips -> ports -> web_apps
        assert {str(ip["address"]) for ip in ips} == {LOOPBACK}
        assert len(links) >= 1
        assert HOSTNAME in {a["hostname"] for a in assets}, (
            f"the resolved host was not persisted: {sorted(a['hostname'] for a in assets)}"
        )
        assert {w["asset_id"] for w in web_apps} <= set(asset_ids)
        assert len(ports) >= 1
        assert all(p["ip_id"] in {ip["id"] for ip in ips} for p in ports)
        assert all(str(p["protocol"]) == "tcp" for p in ports)
        assert all(p["port_number"] == target.port for p in ports)
        assert all(p["state"] == "open" for p in ports)

        # the web app carries the real response values
        wa = web_apps[0]
        assert wa["status_code"] == 200
        assert wa["title"] == "argus-phase14"
        assert wa["server_header"] == "argus-phase14-controlled"

        # ---- provenance: every evidence row points at a real tool run --------
        assert len(tool_runs) >= 2, "both executions must be recorded"
        for ev in evidence:
            assert ev["tool_run_id"] in tool_run_ids, (
                f"evidence {ev['entity_type']} references an unknown tool run"
            )
        # the tool_run_id really is a foreign key, not merely a matching value
        assert conn.execute(
            "SELECT count(*) AS n FROM evidence e "
            "LEFT JOIN tool_runs t ON t.id = e.tool_run_id WHERE t.id IS NULL"
        ).fetchone()["n"] == 0

        # raw_output_ref is shared between the tool run and its evidence
        refs = {t["id"]: t["raw_output_ref"] for t in tool_runs}
        for ev in evidence:
            assert ev["raw_reference"] == refs[ev["tool_run_id"]], (
                "evidence and tool run disagree about the raw output reference"
            )
            assert ev["raw_reference"], "provenance must name the preserved raw output"

        # the two executions are distinguishable by tool
        assert {str(t["tool_name"]) for t in tool_runs} == {"dns", "controlled_http_probe"}

        # every evidence row that names a canonical entity names a row that exists
        for ev in evidence:
            table = {
                "asset": "assets",
                "ip": "ips",
                "asset_ip": "asset_ips",
                "web_app": "web_apps",
            }.get(ev["entity_type"])
            if table is None or ev["entity_id"] is None:
                continue
            assert conn.execute(
                f"SELECT 1 AS ok FROM {table} WHERE id = %s", (ev["entity_id"],)
            ).fetchone(), f"{ev['entity_type']} evidence points at a missing row"

        kinds = {str(e["entity_type"]) for e in evidence}
        assert "asset" in kinds
        assert "web_app" in kinds or "observed_web_app" in kinds
