# Security Audit — presidio-hardened-x402

**Audit date:** 2026-06-03
**Commit audited:** `bfd2f5a` (branch `claude/security-audit-1kEVn`)
**Package version:** 0.4.0
**Scope:** Full source audit of the `presidio_x402` library, the Docker/Helm
deployment surface, CI configuration, and dependency posture.
**Auditor:** Automated security review (Claude Code)

---

## 1. Executive summary

`presidio-hardened-x402` is a client-side hardening layer for the x402
"HTTP 402 Payment Required" agent-payment flow. It is a mature, defense-in-depth
codebase that has already absorbed several prior audit cycles (findings F-A…F-E,
F1…F3, and adversary chains 01–08). The headline controls — PII redaction,
spending policy, replay guard, tamper-evident audit log, MPA, and SSRF defenses
on MPA webhooks — are well implemented, use constant-time HMAC comparison where
appropriate, fail closed, and are backed by a strong test suite.

This audit found **no Critical or High severity vulnerabilities**. It did,
however, identify **three Medium** issues where a hostile 402 server can weaken
or bypass a control, plus several Low/Informational items. The two most
actionable findings are:

1. **Per-endpoint budget bypass via URL-prefix confusion** (`startswith`
   matching) — a hostile origin can borrow a *higher* trusted per-endpoint
   limit (F-01).
2. **Trusted-wallet allowlist bypass** — the allowlist origin is derived from
   the *post-redaction* URL, so PII redaction of the host can silently move the
   origin out of the allowlist and disable the `pay_to` check (F-02).

All findings are confirmed against the source at the audited commit; reproducers
are inlined where useful.

### Findings at a glance

| ID | Severity | Title | Component |
|----|----------|-------|-----------|
| F-01 | Medium | Per-endpoint spending limit bypass via `startswith` prefix confusion | `policy_engine.py` |
| F-02 | Medium | Trusted-wallet allowlist bypass — origin computed from redacted URL | `gateway.py` |
| F-03 | Medium | Budget + replay slot consumed before payment commit (MPA-deny / sign-fail) | `gateway.py` |
| F-04 | Low | Unbounded recursion on hostile `extra` / deeply nested header JSON → uncaught `RecursionError` DoS | `gateway.py`, `pii_filter.py` |
| F-05 | Low | Blocking `socket.getaddrinfo` on the async path stalls the event loop; no per-lookup timeout | `mpa.py` |
| F-06 | Low | Remote-screening mode is a single point of failure for the 3 primary metadata fields (no local defense-in-depth) | `gateway.py` |
| F-07 | Low | Original signer/network exception retained on `__cause__` can leak key material to caller logs | `gateway.py` |
| F-08 | Low | MPA crypto countersignature is not bound to a nonce/timestamp (replayable after replay-TTL) | `mpa.py` |
| F-09 | Low | LangChain adapter `aclose()` references a non-existent attribute (`_http`) | `adapters/langchain.py` |
| I-01 | Info | `maxAmountRequired` treated as a USD decimal, but x402 `exact` uses atomic token units | `gateway.py` |
| I-02 | Info | Homoglyph normalisation map is partial (Cyrillic-only) | `pii_filter.py` |
| I-03 | Info | `SECURITY.md` "Supported Versions" table is stale (lists 0.3.x as current; package is 0.4.0) | `SECURITY.md` |
| I-04 | Info | Container base image and spaCy model are not digest/version pinned | `docker/Dockerfile` |
| I-05 | Info | Default per-process HMAC keys are insecure unless env vars are set (documented, fail-noisy) | `audit_log.py`, `replay_guard.py` |

---

## 2. Methodology

* Manual line-by-line review of every module under `src/presidio_x402/`,
  the adapters, the FastAPI sidecar, the Dockerfile, the Helm deployment, and CI.
* Threat model framed by `PRESIDIO-REQ.md` §"Security Model": the primary
  adversary is a **malicious 402 server** that fully controls the 402 response
  (headers, `accepts[]`, `resource`, `payTo`, `description`, `reason`, `extra`).
* Each control was traced for ordering, fail-open paths, untrusted-input
  handling, and bypass conditions.
* Suspected bypasses were confirmed with standalone reproducers (inlined below).
* Prior audit closures were cross-referenced to avoid re-reporting fixed issues.

---

## 3. Detailed findings

### F-01 — Per-endpoint spending limit bypass via `startswith` prefix confusion
**Severity:** Medium · **CWE-697 (Incorrect Comparison) / CWE-20** ·
`src/presidio_x402/policy_engine.py:129-138`

`_matching_endpoint_prefix` matches a resource URL to a configured per-endpoint
budget using raw string `startswith`:

```python
parsed = urlparse(resource_url)
base = f"{parsed.scheme}://{parsed.netloc}"
for prefix in candidates:
    if resource_url.startswith(prefix) or base.startswith(prefix):
        return prefix
```

Because the comparison has no host-boundary awareness, a hostile origin whose
hostname merely *begins with* a trusted prefix is matched to that prefix's
budget. If the trusted endpoint carries a **higher** per-endpoint limit than the
operator would grant an unknown host, the attacker inherits it.

**Reproducer (confirmed):**
```
per_endpoint = {"https://api.example.com": 5.00}      # generous trusted limit
evil         =  "https://api.example.com.attacker.com/drain"
_matching_endpoint_prefix(evil) -> "https://api.example.com"   # match!
```

`https://api.example.com.attacker.com` is an entirely attacker-controlled
domain, yet it is granted the `$5.00` budget intended only for
`api.example.com`. The same flaw allows a path-prefix sibling
(`https://api.example.com.evil/...`) to escape a *tighter* per-endpoint cap onto
a different host.

**Impact:** Mis-application of per-endpoint budget caps — either loosening
(wallet-drain headroom) or, in the inverse direction, mis-attributing spend.
The global `daily_limit_usd` still applies as a backstop, which caps blast
radius and keeps this at Medium.

**Recommendation:** Match on parsed-URL boundaries, not raw `startswith`.
Compare the scheme+host exactly and require the path prefix to align on a `/`
boundary, e.g.:
```python
def _host_and_path_match(prefix: str, url: str) -> bool:
    p, u = urlsplit(prefix), urlsplit(url)
    if (p.scheme, p.netloc) != (u.scheme, u.netloc):
        return False
    pp = p.path.rstrip("/")
    return u.path == pp or u.path.startswith(pp + "/") or pp == ""
```
This mirrors the exact-origin discipline already used for `trusted_wallets`.

---

### F-02 — Trusted-wallet allowlist bypass: origin derived from the redacted URL
**Severity:** Medium · **CWE-348 (Use of Less Trusted Source) / CWE-693** ·
`src/presidio_x402/gateway.py:497-514`

The `trusted_wallets` control (a `pay_to` allowlist keyed by resource origin,
added in v0.4.0 to defeat wallet-substitution attacks) computes the lookup key
from `details.resource_url` **after** PII redaction has rewritten that field:

```python
# Section 1 (redact mode) replaces resource_url with the redacted clean_url:
details = replace(details, resource_url=clean_url, ...)
...
# Section 2 then keys the allowlist off the already-redacted URL:
if self._trusted_wallets is not None:
    origin = _resource_origin(details.resource_url)   # <-- redacted URL
    allowed = self._trusted_wallets.get(origin)
    if allowed is not None and details.pay_to not in allowed:
        raise X402PaymentError(...)
```

If redaction alters the **host** portion of the URL, `_resource_origin` produces
a different origin string, the allowlist lookup misses, `allowed is None`, and
the design's "origin absent from the map is unrestricted" rule causes the wallet
check to be **silently skipped** — allowing any `pay_to`.

This happens whenever the host matches a regex PII pattern. The `IP_ADDRESS`
pattern redacts IP-literal hosts, and the `US_SSN`/`PHONE_NUMBER` patterns can
match digit-laden DNS labels.

**Reproducer (confirmed):**
```
IP-literal host:
  original origin : https://10.20.30.40:8080
  after redaction : https://<IP_ADDRESS>:8080      # allowlist keyed on the
                                                    # original origin no longer
                                                    # matches -> check skipped

domain w/ SSN-shaped label:
  https://node-555-01-2345.example.com  ->  https://node-<US_SSN>.example.com
```

An operator who allowlists an IP-literal origin (common for internal
facilitators) gets **zero** wallet protection for that origin: the very control
meant to stop `pay_to` substitution is disabled by the redaction step that runs
just before it.

**Impact:** The wallet-hijack defense (chain-06 mitigation) is bypassable for
any origin whose host can be redacted. Combined with a DNS-poisoning /
hostile-server scenario this re-opens recipient substitution.

**Recommendation:** Key the allowlist off the **original** resource origin, the
same way the replay fingerprint already deliberately uses the pre-redaction URL
(`gateway.py:415, 539`). Capture `original_resource_url` at function entry and
pass it to `_resource_origin`. The host is not PII and should never be redacted
for security-control keying.

---

### F-03 — Budget and replay slot are committed before the payment is committed
**Severity:** Medium · **CWE-362 (race/ordering) / CWE-840 (business-logic)** ·
`src/presidio_x402/gateway.py:519-587` and `:356-373`

Inside `_apply_security_controls` the control order is:

1. PII filter → 2. trusted-wallet → **3. `policy.check_and_record` (commits
spend)** → **4. `replay.check_and_record` (commits fingerprint)** → 5. MPA
approval → return. Only *after* the function returns does `_request` call
`_invoke_signer`.

Consequently, the spend ledger and the replay fingerprint are durably recorded
**before** MPA is evaluated and **before** the payment is ever signed. Two
failure modes follow:

* **MPA-denied / MPA-timeout payment still consumes budget and a replay slot.**
  Because policy+replay record at steps 3–4 and MPA denies at step 5, a denied
  high-value attempt has already (a) charged the daily/endpoint ledger and
  (b) burned the payment fingerprint.
* **The documented crypto-mode MPA retry workflow is broken by the replay
  guard.** `PRESIDIO-REQ.md` / `mpa.py` describe seeing the 402, collecting
  countersignatures out-of-band, then retrying. The first (signature-less)
  attempt records the fingerprint at step 4; the legitimate retry with valid
  signatures then fails with `ReplayDetectedError` for the *same* canonical
  payment.
* **Signer failure leaks budget.** If `_invoke_signer` raises
  (`gateway.py:362-373`), the spend has already been recorded and the
  fingerprint burned, but no payment was made. A hostile server able to induce
  repeated signer failures can drain the *accounting* budget (denying legitimate
  small payments) and block legitimate retries — an availability attack against
  the wallet's own governance.

**Impact:** Budget-accounting integrity loss and self-inflicted DoS on
legitimate retries; the documented MPA crypto workflow does not work as
specified.

**Recommendation:** Make the commit atomic with the payment outcome. Either:
* Move `policy.check_and_record` and `replay.check_and_record` to *after*
  successful signing (check first, record on success), or
* Implement compensating rollback (`ledger.refund(...)`,
  `replay.release(fingerprint)`) on MPA denial/timeout and signer failure.
For replay specifically, only record the fingerprint once a payment token is
actually produced, so an un-signed/denied attempt does not poison the retry.

---

### F-04 — Unbounded recursion on hostile `extra` / nested header JSON → uncaught `RecursionError`
**Severity:** Low · **CWE-674 (Uncontrolled Recursion)** ·
`src/presidio_x402/gateway.py:121,443` · `src/presidio_x402/pii_filter.py:338-367`

The 64 KiB header cap (F3, 2026-05-17) bounds *byte length* but not *nesting
depth*. A 402 server can send a small payload that is deeply nested:

* `json.loads` in `_parse_402_header` raises **`RecursionError`** on deeply
  nested input — and the surrounding `except` only catches
  `json.JSONDecodeError`, so the `RecursionError` propagates uncaught (and
  bypasses the sanitised `PAYMENT_ERROR` audit path).
* `PIIFilter.scan_dict` recurses through attacker-controlled `extra` with no
  depth guard, so a nested `extra` dict/list reaches the interpreter recursion
  limit and raises `RecursionError` as well.

**Reproducer (confirmed):**
```
payload = "[" * 6000 + "]" * 6000      # 12 000 bytes, < 64 KiB cap
json.loads(payload)  -> RecursionError  (NOT caught by the JSONDecodeError handler)
```

**Impact:** A hostile 402 response crashes the request handling path with an
unhandled `RecursionError` instead of a clean `X402PaymentError`, and the event
is not recorded through the redaction-safe audit path. Low severity because it
is per-request and the client owns the request lifecycle, but it is an
availability/robustness gap on fully untrusted input.

**Recommendation:**
* Broaden the `_parse_402_header` parse guard to also catch `RecursionError`
  (and `ValueError`) and re-raise as `X402PaymentError("Invalid X-PAYMENT header
  JSON")`.
* Add a `max_depth` parameter to `scan_dict` (e.g. 32) that treats over-deep
  structures as opaque/blocked, and bound `json.loads` nesting (parse then
  validate depth, or wrap in a recursion-limited context).

---

### F-05 — Blocking DNS resolution on the async path stalls the event loop
**Severity:** Low · **CWE-400 (Uncontrolled Resource Consumption)** ·
`src/presidio_x402/mpa.py:129-142, 446-471`

`_resolve_and_check_host` (the DNS-rebinding SSRF defense) calls the **blocking**
`socket.getaddrinfo` directly inside the async `_request_single_approval`
coroutine, with no timeout. While the overall MPA call is bounded by
`asyncio.wait_for(..., timeout_seconds)`, that timeout cannot interrupt a
synchronous C call already in progress — and during resolution the **entire
event loop is blocked**, stalling all other concurrent approvals and any other
client work on that loop.

**Impact:** A malicious or slow DNS authority for one approver hostname degrades
the whole client. Low severity (requires a slow/hostile resolver and only
affects MPA-configured deployments), but it undercuts the parallel-approval
design and the timeout guarantee.

**Recommendation:** Run the resolution off-loop —
`await asyncio.get_running_loop().getaddrinfo(host, None)` — which both yields
to the loop and is covered by the surrounding `wait_for` timeout.

---

### F-06 — Remote-screening mode is a single point of failure for the primary fields
**Severity:** Low / Informational · **CWE-654 (Reliance on a Single Factor)** ·
`src/presidio_x402/gateway.py:420-443`

With `remote_screening=True`, `resource_url`, `description`, and `reason` are
scanned **only** by the remote service; the local `PIIFilter` is applied solely
to the `extra` dict (defense-in-depth for the smuggle channel) and to exception
messages. If the screening service mis-redacts, returns an empty
`entities_found`, is silently degraded, or is reachable over a valid-TLS but
adversarial path, PII in the three primary fields passes through unredacted with
no local backstop. `ScreeningClient.scan_payment_fields` also fully trusts the
service's `redacted_*` strings.

**Impact:** The zero-trust-metadata principle (`PRESIDIO-REQ.md` §Design
Principles) is weakened to "trust the remote screener" for the main fields.

**Recommendation:** Run the local `PIIFilter` over the remote-returned strings as
a cheap defense-in-depth pass (it is regex-fast), or at minimum document
prominently that remote mode removes the local guarantee for the three primary
fields and recommend `pii_action="block"` fail-closed behavior when the remote
returns an unexpected/empty result.

---

### F-07 — Signer/network exception retained on `__cause__` may leak secrets to caller logs
**Severity:** Low · **CWE-209 (Information Exposure Through an Error Message)** ·
`src/presidio_x402/gateway.py:361-373`

The audit record for a signing failure is correctly truncated and PII-redacted.
However, the re-raised exception preserves the original via
`raise X402PaymentError("Payment signing failed") from exc`. The original `exc`
from a wallet/signer SDK can contain key material, mnemonics, or raw payloads in
its message/traceback. Any caller that logs the exception **chain** (the default
for most frameworks) writes that unredacted content to its own logs — outside
this library's sanitised audit path. The same pattern exists for the
`_parse_402_header` cause chain, where the comment explicitly notes the raw JSON
remains on `__cause__`.

**Impact:** Potential secret/PII leakage into downstream logs, defeating the
library's own redaction guarantees one layer up.

**Recommendation:** For the *signing* path specifically, consider
`raise X402PaymentError("Payment signing failed") from None` (drop the cause) and
log only the truncated+redacted message internally, since signer exceptions are
the highest-risk source of key material. Document that callers should not log
`__cause__` of `X402PaymentError`.

---

### F-08 — MPA crypto countersignature lacks nonce/timestamp binding
**Severity:** Low · **CWE-294 (Authentication Bypass by Capture-Replay)** ·
`src/presidio_x402/mpa.py:248-263, 336-356`

The crypto-mode countersignature is an HMAC over the canonical payment fields
(`resource_url`, `pay_to`, `amount`, `currency`, `network`, `deadline_seconds`,
`amount_usd`) with **no nonce, request-id, or timestamp**. A captured valid
countersignature remains valid for any future payment with identical fields.
Within the replay-TTL window the ReplayGuard blocks the duplicate, but **after
TTL expiry** an attacker who once observed a valid approver signature could
reuse it to satisfy MPA for an identical payment. HMAC comparison itself is
constant-time (`hmac.compare_digest`) — good.

**Impact:** Bounded replay of approver authorization for identical recurring
payments outside the replay window.

**Recommendation:** Bind the countersignature to the per-attempt `request_id`
(already computed) plus a freshness timestamp/expiry, and have the engine reject
signatures whose embedded timestamp is stale.

---

### F-09 — LangChain adapter `aclose()` references a non-existent attribute
**Severity:** Low (robustness) · `src/presidio_x402/adapters/langchain.py:106-108`

```python
async def aclose(self) -> None:
    await self._client._http.aclose()   # attribute is _httpx, not _http
```

`HardenedX402Client` exposes `_httpx`, not `_http`, so `aclose()` raises
`AttributeError` and the underlying httpx connection pool is never closed —
a resource leak for long-lived LangChain agents.

**Recommendation:** Call `await self._client.aclose()` (the client's own public
close method).

---

## 4. Informational observations

* **I-01 — Amount units.** `_amount_to_usd` parses `maxAmountRequired` directly
  as a USD float, but the x402 `exact` scheme conventionally expresses amounts
  in **atomic token units** (e.g. `"10000"` = 0.01 USDC at 6 decimals). The
  README/docstrings use human-decimal examples, so the library's contract is
  self-consistent, but an integrator wiring a spec-conformant facilitator will
  see policy limits compare against mis-scaled values (fail-closed over-blocking,
  or under-counting if limits are mis-set in atomic units). Recommend an explicit
  per-currency decimals table and a documented amount convention. (`gateway.py:163`)
* **I-02 — Homoglyph coverage.** `_HOMOGLYPH_FOLD` covers Cyrillic look-alikes
  only; Greek and other confusable scripts are not folded, so NFKC-stable
  homoglyph evasion of the regex layer remains partially possible. Documented as
  "manual coverage." Consider the `confusables`/Unicode TR39 data set in `nlp`
  deployments. (`pii_filter.py:37-66`)
* **I-03 — Stale SECURITY.md.** The "Supported Versions" table lists 0.3.x as
  current and omits 0.4.x; the package is 0.4.0. Update to avoid signalling an
  unsupported release. (`SECURITY.md:5-9`)
* **I-04 — Supply-chain pinning.** `docker/Dockerfile` uses `python:3.12-slim`
  (tag, not digest) and `spacy download en_core_web_sm` (unpinned model), the
  acknowledged chain-01/chain-08 residuals deferred to v0.5.0. The HEALTHCHECK
  `urllib.request.urlopen` has no timeout. Digest-pin the base image and pin the
  model wheel when those milestones land. (`docker/Dockerfile`)
* **I-05 — Default HMAC keys.** Both the audit-chain key
  (`PRESIDIO_X402_CHAIN_KEY`) and the replay fingerprint key
  (`PRESIDIO_X402_FINGERPRINT_KEY`) fall back to a fresh per-process random key
  when unset, disabling cross-process/cross-restart guarantees. This is **handled
  well**: the fallback logs at ERROR level and is documented as a deploy-time
  defect. v0.5.0's planned hard startup-gates
  (`PRESIDIO_X402_REQUIRE_*_KEY`) are the right closure. No change required, noted
  for completeness. (`audit_log.py:59-81`, `replay_guard.py:37-67`)

---

## 5. Positive observations (controls verified sound)

* **Constant-time comparisons** for all HMAC verification
  (`hmac.compare_digest` in MPA crypto, MPA webhook response, replay fingerprint
  handling).
* **MPA SSRF defense** is genuinely layered: HTTPS-only + IP-literal blocklist at
  config time, plus post-DNS re-resolution against RFC1918/loopback/link-local/
  IMDS/CGNAT ranges at request time (chain-07 closed). Logic is correct.
* **Replay fingerprint canonicalisation** (lower-cased `pay_to`, upper-cased
  `currency`, JSON-array canonical form) correctly closes the case-toggle and
  delimiter-injection bypasses (F1/F-D).
* **PolicyEngine TOCTOU** is correctly serialised: the aggregate/per-endpoint
  check-and-record runs under a single `_check_lock`, and the Redis replay store
  uses atomic `SET NX EX`.
* **Audit chain** advances `_prev_hmac` even when a writer throws, so a dropped
  entry surfaces as a chain break (fail-evident) rather than being hidden.
* **Header DoS cap** (64 KiB) and **non-finite amount rejection** (`nan/inf`
  bypass of IEEE-754 limit checks) are both present and correct.
* **`extra`-channel PII smuggling** is closed by the local `scan_dict` pass even
  in remote-screening mode (F-A).
* **Exception messages in audit records** are truncated and re-scanned for PII
  before emission.
* **Container** runs as a non-root UID 1001 with a dedicated group.

---

## 6. Prioritised remediation plan

1. **F-02** — key `trusted_wallets` off the original (pre-redaction) origin.
   Small, high-value fix; restores a v0.4.0 security control. *(quick)*
2. **F-01** — replace `startswith` per-endpoint matching with boundary-aware
   host+path matching. *(quick)*
3. **F-03** — record spend/replay only on payment success (or add compensating
   rollback); fixes both the budget-leak DoS and the broken MPA crypto retry.
   *(moderate — touches control ordering; add regression tests)*
4. **F-04** — catch `RecursionError` in header parsing; add `max_depth` to
   `scan_dict`. *(quick)*
5. **F-05, F-07, F-09** — async DNS resolution; drop signer-exception cause;
   fix adapter `aclose`. *(quick)*
6. **F-06, F-08, I-01..I-04** — schedule with the v0.5.0 hardening milestone.

None of the findings block release on their own, but **F-01, F-02, and F-03**
each let a hostile 402 server weaken a control the library advertises, and are
worth fixing before the next tag.

---

*End of report.*
