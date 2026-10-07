"""Network port/service discovery adapters (Phase 20A).

Currently houses the Nmap TCP port/service discovery adapter. Port discovery is a
*separate discovery surface* from HTTP probing: it is authorized by the same scope
guard, executed by the same controlled Tool Runner, and its observations are
recorded as facts (``ports`` rows + evidence), never as findings.
"""