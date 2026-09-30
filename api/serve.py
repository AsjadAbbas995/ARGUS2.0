"""Serve seam for ARGUS (Phase 13).

Wires the committed ``Orchestrator`` + the committed PostgreSQL-backed
``Repositories`` implementation of the ``Storage`` contract + the committed
``DnsResolverAdapter`` into the committed ``create_app`` factory, so the API can
be served against the authoritative store from ``05_DATA_MODEL.md``.

API key precedence:
  1. ``ARGUS_API_KEY`` environment variable
  2. the explicit ``api_key`` argument (used by controlled tests and embedders)

There is deliberately **no** third fallback. A credential committed to the
repository is published, not secret, and it gates the route that drives real
network requests, so production startup fails loudly when no key is configured
instead of authenticating on a guessable literal. A blank or whitespace-only key
is treated as absent. The key is never logged, never persisted, and never placed
in a run's ``configuration_snapshot``.

Storage precedence:
  1. an explicitly injected ``storage`` (tests / embedding)
  2. PostgreSQL via ``ARGUS_DATABASE_URL`` (or ``database_url=``) -- production
  3. ``in_memory=True`` -- an explicit, opt-in development mode only

There is deliberately **no** silent fallback to ``MemoryStorage``: if
``ARGUS_DATABASE_URL`` is unset, production startup fails loudly instead of
serving an unauditable, non-durable store. ``MemoryStorage`` remains a test
double implementing the same ``Storage`` contract.

The factory is uvicorn-``--factory`` compatible (zero-argument callable
returning a ``FastAPI`` instance); it constructs the whole injection graph so
``api/server.py`` never needs to know how storage/adapters are built.
"""

from __future__ import annotations

import logging
import os
from dataclasses import replace
from pathlib import Path
from typing import Callable, Mapping, Optional

from api.server import create_app
from core.config import Config, ConfigError, DatabaseConfig, ScopeConfig
from core.memory_storage import MemoryStorage
from core.orchestrator import Orchestrator, ToolRunOutcome
from core.rate_limiter import RateLimiter
from core.scope_guard import ScopeGuard, ScopeRule, ScopeRuleType, extract_host
from core.tool_runner import ToolRunner, ToolRunnerError
from database.models.entities import ToolRun
from recon.base import ToolAdapter
from recon.dns.resolver import DnsResolverAdapter, make_resolver
from recon.ingest import plan_ingestion
from recon.normalize import normalize_hostname
from recon.web.httpx_probe import HttpxProbeAdapter

log = logging.getLogger(__name__)

#: Environment variable holding the PostgreSQL URL for the served runtime. Same
#: variable name ``core.config.DatabaseConfig`` already reads.
DATABASE_URL_ENV = "ARGUS_DATABASE_URL"

#: Environment variable holding the operator API key. The served runtime has no
#: default: without it, startup fails.
API_KEY_ENV = "ARGUS_API_KEY"

#: Task type -> adapter factory. Dispatch is by task type so a task is executed by
#: the tool that actually implements it; previously every task type was routed to
#: the DNS resolver, so an ``http_probe`` task silently produced a DNS result.
#:
#: A type that appears in neither tuple has no adapter and is refused. See
#: :class:`UnknownTaskType`.
DEFAULT_ADAPTER_TYPES: tuple[str, ...] = ("dns_resolve", "dns", "resolve")
DEFAULT_HTTP_PROBE_TYPES: tuple[str, ...] = ("http_probe", "httpx", "web_probe")


class ServeConfigurationError(RuntimeError):
    """Raised when the serve seam cannot build a production storage backend."""


def _resolve_api_key(api_key: Optional[str]) -> str:
    """The operator key the served runtime will authenticate against.

    ``ARGUS_API_KEY`` wins over the explicit argument, and there is no third
    source. A missing, empty or whitespace-only key raises
    :class:`ServeConfigurationError` rather than yielding an app that would
    either reject every request or, far worse, accept a guessable one.

    The key is returned to the caller and stored only in
    ``app.state.argus_api_key``. It is never logged, never written to the
    database, and never included in a run's ``configuration_snapshot``.
    """
    raw = os.environ.get(API_KEY_ENV)
    candidate = raw if raw is not None and raw.strip() else api_key
    effective = str(candidate).strip() if candidate else ""
    if not effective:
        raise ServeConfigurationError(
            f"production serve requires an API key: set {API_KEY_ENV} (or pass "
            f"api_key=). There is no default credential -- a key committed to the "
            f"repository is a published key, and it gates the route that runs real "
            f"tools against real targets."
        )
    return effective


class UnknownTaskType(ValueError):
    """No adapter is registered for this task type.

    Raised *before* any adapter is constructed, so an unrecognised task type can
    never be executed by some other tool. The orchestrator records the exception as a
    task failure and keeps the run moving, which is the documented failure state.

    This is a configuration fault, not a transient one: it is a ``ValueError`` so a
    caller can distinguish "this run was misconfigured" from "the tool was missing".
    """


class ServedExecution:
    """The served ``run_tool`` seam: task type -> adapter -> controlled Tool Runner.

    This is the last boundary before a target. It preserves the documented trust
    chain of ``02_ARCHITECTURE.md`` (``Scope Guard -> Rate Limiter -> Tool Adapter ->
    Tool Runner -> Target``): the orchestrator has already enforced scope and taken a
    rate-limit permit before this is called, and the adapter re-validates scope
    itself (``ToolAdapter.validate``) because both are documented boundaries.

    The runner is constructed once and reused so raw output lands under a single,
    configured ``storage/raw`` root rather than a fresh default per task.
    """

    def __init__(
        self,
        *,
        adapters: Mapping[str, Callable[[], ToolAdapter]],
        runner: ToolRunner,
        database_url: str = "",
    ) -> None:
        self._adapters = dict(adapters)
        self._runner = runner
        self._database_url = database_url or ""

    def known_task_types(self) -> tuple[str, ...]:
        """The task types this composition can execute, sorted."""
        return tuple(sorted(self._adapters))

    def adapter_for(self, task) -> ToolAdapter:
        """The adapter that implements this task's type -- or a hard failure.

        An unknown type is never routed to a substitute tool. Falling back to the DNS
        resolver meant a typo, a task type from a newer planner, or an ``http_probe``
        the composition did not know all silently produced a *DNS answer* recorded as a
        successful probe: a wrong result reported as a success, which is worse than no
        result at all. Refusing here happens before an adapter exists, so nothing is
        constructed, no subprocess starts and no target is contacted.
        """
        task_type = getattr(task, "type", "")
        factory = self._adapters.get(task_type)
        if factory is None:
            known = ", ".join(self.known_task_types()) or "(none registered)"
            raise UnknownTaskType(
                f"no adapter is registered for task type {task_type!r}; "
                f"known task types: {known}"
            )
        return factory()

    def execution_config(self, snapshot) -> Optional[Config]:
        """Rebuild the typed configuration from the run's persisted snapshot.

        The snapshot is the authoritative record of what the run was created with, so
        the adapter is handed *that* configuration rather than a process-local
        default. The snapshot deliberately carries no ``database`` section (see
        ``core.config.run_snapshot_from_dict``), so the resolved serve-time URL is
        supplied here purely to satisfy the ``Config`` shape.
        """
        if not isinstance(snapshot, dict) or not snapshot:
            return None
        data = dict(snapshot)
        data["database"] = {"url": self._database_url or "unconfigured"}
        try:
            return Config.from_dict(data)
        except ConfigError:
            # A snapshot that no longer validates (e.g. a column edited by hand)
            # must not silently fall back to permissive defaults: the adapter runs
            # with no configuration, which for every committed adapter means the
            # conservative default rather than an opened-up policy.
            return None

    def run(self, task, scope=None, config=None) -> ToolRunOutcome:
        """Execute ``task`` and return its ``ToolRun`` **with** its parsed artifacts.

        Phase 14: ``__call__`` historically returned only the ``ToolRun``, silently
        discarding the normalized observations the adapter had just produced. The
        served wiring points the orchestrator's ``run_tool`` seam here so those
        artifacts reach ingestion; ``__call__`` is kept returning a bare
        ``ToolRun`` for every existing caller and test.
        """
        adapter = self.adapter_for(task)
        execution = adapter.execute(
            task,
            runner=self._runner,
            config=self.execution_config(config),
            # An absent guard is deny-all, never permissive: an un-scoped seam fails
            # closed rather than resolving something nobody authorized.
            scope=scope if scope is not None else ScopeGuard.from_config(ScopeConfig()),
        )
        return ToolRunOutcome(
            tool_run=ToolRun(
                task_id=task.id,
                tool_name=execution.tool,
                command=list(execution.command),
                exit_code=execution.exit_code,
                raw_output_ref=execution.raw_output_ref,
            ),
            artifacts=tuple(execution.artifacts),
        )

    def __call__(self, task, scope=None, config=None) -> ToolRun:
        return self.run(task, scope=scope, config=config).tool_run


#: Inject the DNS resolution outcome into an ``Orchestrator.run_tool`` seam.
def _dns_run_tool(
    task,
    resolver_fn=None,
    timeout: float = 3.0,
    *,
    runner: Optional[ToolRunner] = None,
    config=None,
    scope: Optional[ScopeGuard] = None,
) -> ToolRun:
    adapter = DnsResolverAdapter(
        resolver_fn=resolver_fn or make_resolver(timeout=timeout),
        timeout=timeout,
    )
    execution = adapter.execute(
        task,
        runner=runner if runner is not None else ToolRunner(),
        config=config,
        scope=scope if scope is not None else ScopeGuard.from_config(ScopeConfig()),
    )
    return ToolRun(
        task_id=task.id,
        tool_name=execution.tool,
        command=list(execution.command),
        exit_code=execution.exit_code,
        raw_output_ref=execution.raw_output_ref,
    )


def _postgres_storage(database_url: Optional[str]):
    """Build the production ``Storage``: a migrated PostgreSQL repository facade.

    Migrations are applied here because the committed CLI is still a no-op, so
    this is the only entry point that can bring a fresh database up to the
    committed schema. ``ensure_migrated`` is idempotent.
    """
    if not database_url:
        raise ServeConfigurationError(
            f"production serve requires PostgreSQL: set {DATABASE_URL_ENV} (or pass "
            f"database_url=). In-memory storage is available only via the explicit "
            f"in_memory=True development flag; it is never selected implicitly."
        )

    from database.migrate import ensure_migrated
    from database.repositories.all import Repositories
    from database.repositories.base import DatabaseConnection

    connection = DatabaseConnection(database_url)
    raw = connection.connect()
    try:
        ensure_migrated(raw)
    except Exception:
        connection.close()
        raise
    return Repositories(raw)


def _effective_config(config: Optional[Config], database_url: str) -> Config:
    """The typed configuration the served runtime executes with.

    The serve runtime must always have a limits policy, because a served process
    without a rate limiter is an unbounded fan-out. When no configuration is injected
    (the normal deployment) the documented defaults are used, with the resolved
    database URL filled in so the ``Config`` shape is complete. ``Config`` is built
    directly rather than through ``from_dict`` so the absent-URL development mode
    (``in_memory=True`` with no PostgreSQL configured) still yields a usable limits
    policy instead of raising.
    """
    if config is not None:
        return config
    return replace(Config(), database=DatabaseConfig(url=database_url or ""))


def _default_adapters(
    resolver_fn, dns_timeout: float
) -> dict[str, Callable[[], ToolAdapter]]:
    """Build the default task-type -> adapter table.

    Every type the served runtime will execute appears here explicitly. There is no
    substitute: a type outside this table is refused by
    :meth:`ServedExecution.adapter_for` rather than quietly run by another tool.

    ``resolver_fn`` is the test/dev injection point for DNS answers; production uses
    ``make_resolver`` (dnspython-style resolution through the standard library).
    """
    def dns() -> ToolAdapter:
        return DnsResolverAdapter(
            resolver_fn=resolver_fn or make_resolver(timeout=dns_timeout),
            timeout=dns_timeout,
        )

    adapters: dict[str, Callable[[], ToolAdapter]] = {
        kind: dns for kind in DEFAULT_ADAPTER_TYPES
    }
    adapters.update(
        {kind: HttpxProbeAdapter for kind in DEFAULT_HTTP_PROBE_TYPES}
    )
    return adapters


#: Phase 14: the storage method that applies a scope-checked ingestion plan.
_INGEST_METHOD = "ingest_observations"


def _build_ingestor(store, config: Config) -> Optional[Callable[..., None]]:
    """Build the Phase-14 ingestion callback for a served orchestrator.

    Returns ``None`` when the storage cannot persist facts (e.g. ``MemoryStorage``),
    so the orchestrator keeps its exact pre-Phase-14 behaviour instead of calling a
    method that does not exist. The returned callable runs *inside* the
    orchestrator's transaction, so everything it writes commits or rolls back
    together with the ``ToolRun`` and the task's terminal state.
    """
    if not callable(getattr(store, _INGEST_METHOD, None)):
        return None

    limit = config.limits.max_artifacts_per_run
    # An absent guard denies everything: with no authoritative guard no observed
    # destination can be classified, and promoting an unclassified one would reopen
    # the Phase 13 boundary. Everything is then recorded as an observation instead.
    deny_all = ScopeGuard.from_config(ScopeConfig())

    def ingest(task, tool_run: ToolRun, artifacts, run, scope) -> None:
        if not artifacts:
            return
        plan = plan_ingestion(
            artifacts,
            scope=scope if scope is not None else deny_all,
            source=tool_run.tool_name,
            target_host=normalize_hostname(extract_host(task.target)),
            max_artifacts=limit,
        )
        for observation in plan.out_of_scope:
            # ``evidence`` has no reason column, so the scope denial is logged here
            # while the observation itself is preserved (without a graph row).
            log.info(
                "out-of-scope %s %r not promoted: %s",
                observation.kind,
                observation.value,
                observation.reason,
            )
        if plan.truncated:
            log.warning(
                "tool %s exceeded limits.max_artifacts_per_run=%d; %d artifact(s) dropped",
                tool_run.tool_name,
                limit,
                plan.truncated,
            )
        if plan.unrecognized:
            log.warning(
                "tool %s produced %d unrecognized artifact(s); no records created",
                tool_run.tool_name,
                plan.unrecognized,
            )
        getattr(store, _INGEST_METHOD)(
            plan,
            tool_run_id=tool_run.id,
            raw_output_ref=tool_run.raw_output_ref,
            program_id=run.program_id,
        )

    return ingest


def create_serve_app(
    *,
    api_key: Optional[str] = None,
    storage=None,
    resolver_fn=None,
    database_url: Optional[str] = None,
    in_memory: bool = False,
    config: Optional[Config] = None,
    runner: Optional[ToolRunner] = None,
    adapters: Optional[Mapping[str, Callable[[], ToolAdapter]]] = None,
    dns_timeout: float = 3.0,
) -> "object":
    """Build the fully-wired FastAPI app for serving ARGUS.

    ``api_key`` is used when ``ARGUS_API_KEY`` is unset. There is no fallback
    credential: with neither the environment variable nor an explicit key,
    startup raises :class:`ServeConfigurationError` rather than serving an API
    protected by a value that is published in this repository.
    ``storage``/``resolver_fn`` are optional injection points for tests. With
    neither ``storage`` nor ``in_memory``, the app is backed by PostgreSQL
    (``database_url`` or ``ARGUS_DATABASE_URL``) and refuses to start if no
    database is configured.

    The composition wires the full documented execution chain, in order
    (``02_ARCHITECTURE.md``): ``Scope Guard -> Rate Limiter -> Tool Adapter ->
    Tool Runner -> Target``, with PostgreSQL on both sides.

    * ``config`` supplies the typed policy. Its ``limits`` always produce a real
      :class:`RateLimiter`; a served process never runs unthrottled.
    * ``runner`` injects the controlled subprocess boundary and is reused for every
      task so raw output lands under one configured ``storage.raw`` root.
    * ``adapters`` overrides the task-type -> adapter table. Production uses
      :func:`_default_adapters`; a controlled harness may inject an adapter that
      drives the real ``ToolRunner`` against a local target.
    """
    # Authentication is a startup precondition, checked before anything is
    # constructed: there is no committed default key to fall back to.
    effective_key = _resolve_api_key(api_key)
    if storage is not None:
        store = storage
    elif in_memory:
        store = MemoryStorage()
    else:
        store = _postgres_storage(database_url or os.environ.get(DATABASE_URL_ENV))

    resolved_url = database_url or os.environ.get(DATABASE_URL_ENV) or ""
    effective_config = _effective_config(config, resolved_url)
    tool_runner = runner if runner is not None else ToolRunner(
        raw_dir=Path(effective_config.storage.raw_dir)
    )

    default_adapters = _default_adapters(resolver_fn, dns_timeout)
    if adapters:
        default_adapters.update(adapters)

    execution = ServedExecution(
        adapters=default_adapters,
        runner=tool_runner,
        database_url=resolved_url,
    )
    # A real limiter, always. Previously the served composition passed none, so every
    # served execution bypassed the rate limiter the architecture documents.
    limiter = RateLimiter.from_config(effective_config.limits)
    # ``scope=`` is load-bearing: the orchestrator probes this signature and hands
    # over the run's real guard, so the adapter validates against the scope the run
    # was created with. Without it the adapter fell back to its own empty
    # ``ScopeConfig()``, which denies every target, making production execution
    # fail closed with no possible cause. The orchestrator still enforces scope
    # itself, before the tool is reached. ``config=`` likewise carries the run's own
    # persisted configuration into the adapter.
    # Phase 14: run_tool points at ``ServedExecution.run`` so the adapter's parsed
    # artifacts reach ingestion instead of being discarded. ``ingest`` maps and
    # persists them inside the orchestrator's transaction. Both are additive: a
    # run with no artifacts ingests nothing, and every other caller of
    # ``ServedExecution`` still gets a bare ``ToolRun`` from ``__call__``.
    orch = Orchestrator(
        storage=store,
        run_tool=execution.run,
        rate_limiter=limiter,
        ingest=_build_ingestor(store, effective_config),
    )

    app = create_app(orch, api_key=effective_key)
    # Exposed so request handling and controlled harnesses can reach the wired
    # runtime without reaching into the orchestrator: the API layer builds each
    # run's ``configuration_snapshot`` from the served policy, and a restart test
    # can rebuild the same wiring against the same database.
    app.state.argus_config = effective_config
    app.state.argus_database_url = resolved_url
    app.state.argus_orchestrator = orch
    app.state.argus_storage = store
    app.state.argus_execution = execution
    app.state.argus_rate_limiter = limiter
    return app


def serve_factory() -> "object":
    """uvicorn ``--factory`` entrypoint: zero-arg callable -> FastAPI app."""
    return create_serve_app()
