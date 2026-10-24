"""Phase-13 serve seam runtime gate (byte-reliable gate, venv python).

The seam's authority comes from the committed factory only. This gate calls the
committed ``create_serve_app``/``serve_factory`` (the zero-arg uvicorn factory
compatible entrypoint), verifies the returned object is a committed FastAPI app,
and verifies the committed API-key precedence (env > arg > committed default).
"""

from __future__ import annotations

import os
import sys


def _gate() -> int:
    from api.serve import create_serve_app, serve_factory
    from api.server import _API_KEY

    app = create_serve_app()
    fastapi_ok = type(app).__name__ == "FastAPI"
    factory_app = serve_factory()
    factory_ok = type(factory_app).__name__ == "FastAPI"
    key_ok = getattr(app.state, "argus_api_key", None) == _API_KEY

    if not (fastapi_ok and factory_ok and key_ok):
        sys.stdout.write(f"serve_gate=fail fastapi={fastapi_ok} factory={factory_ok} key={key_ok}")
        return 1

    # -- API-key precedence: ARGUS_API_KEY environment variable wins ----------
    os.environ["ARGUS_API_KEY"] = "phase-13-env"
    env_app = create_serve_app()
    env_ok = env_app.state.argus_api_key == "phase-13-env"
    del os.environ["ARGUS_API_KEY"]
    if not env_ok:
        sys.stdout.write("serve_gate=fail env_precedence=False")
        return 1

    sys.stdout.write("serve_gate=ok")
    return 0


if __name__ == "__main__":
    sys.exit(_gate())
