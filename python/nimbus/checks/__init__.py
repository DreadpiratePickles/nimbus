"""Native Prowler-style cloud checks for nimbus.

Each check lives in ``nimbus/checks/<provider>/<service>/<check_id>/`` as
``<check_id>.py`` (a :class:`~nimbus.checks.base.Check` subclass) next to
``<check_id>.metadata.json`` (Prowler metadata shape).  Findings are emitted
in the Go ``model.Finding`` JSON contract so ``cloud-posture ingest --source
native`` can consume them directly.
"""

from .base import Check, CheckResult

__all__ = ["Check", "CheckResult"]
