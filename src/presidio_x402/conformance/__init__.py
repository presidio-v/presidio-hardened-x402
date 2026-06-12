"""Partner-runnable conformance suite for presidio-hardened-x402 (OEM embed kit).

Run against your installed environment with::

    python -m presidio_x402.conformance

The suite verifies — in-process, with no network access — that the installed
library delivers the documented security guarantees end-to-end:

1. The public API surface (everything in ``__all__``) imports.
2. PII in payment metadata is redacted before the signer sees it.
3. ``pii_action="block"`` fails closed on PII.
4. Spending policy blocks an over-limit payment before signing.
5. An identical payment is blocked as a replay; a signer failure rolls back
   the budget + fingerprint (no lost funds accounting, no burned retry slot).
6. The audit log is written and its HMAC chain verifies; a tampered log is
   detected.
7. The x402 binding parses spec-conformant 402 offers and rejects malformed
   ones fail-closed.

Exit code 0 = all checks pass; 1 = at least one failure (fail-closed: an
unexpected exception in any check counts as failure). Intended for OEM
partners to run in their own integration environment/CI.
"""

from __future__ import annotations

from .runner import main, run_all

__all__ = ["main", "run_all"]
