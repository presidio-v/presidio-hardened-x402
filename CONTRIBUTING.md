# Contributing to presidio-hardened-x402

Thanks for your interest. This is security middleware for the x402 payment protocol, so
contributions are held to a somewhat stricter bar than a typical library — the checklist
below is what a change needs to clear before it can be merged.

## Reporting a security vulnerability

**Do not open a public issue for a security vulnerability.** Use the private reporting
process in [SECURITY.md](SECURITY.md) — GitHub Security Advisories, via the repository's
"Security" tab. You will get an acknowledgement within 5 business days.

## Reporting bugs and requesting features

Open a [GitHub issue](https://github.com/presidio-v/presidio-hardened-x402/issues). Search
existing issues first. For a bug, include:

- the library version (`pip show presidio-hardened-x402`) and Python version
- what you expected to happen, and what happened instead
- a minimal reproduction if you can produce one

Please redact real payment metadata, wallet addresses, and personal data from anything you
paste into a public issue.

## How changes are made

All changes go through a pull request against `main`. Direct pushes to `main` are blocked by
branch protection, and every PR must pass the required status checks before it can merge.

1. Fork the repository and create a branch off `main`.
2. Make your change, with tests (see the test policy below).
3. Run the local verification block until it is clean.
4. Update `CHANGELOG.md` under `## [Unreleased]`.
5. Open a PR describing what changed and why.

## Requirements for acceptable contributions

A change is merged when it meets all of the following.

### Style

Formatting and linting are enforced by [ruff](https://docs.astral.sh/ruff/) and are not a
matter of taste — CI rejects anything that does not conform. The configuration lives in
`pyproject.toml`; the settings that most often surprise people:

- line length 99, target Python 3.10
- lint rule sets `E, F, W, I, N, UP, S, B, A, C4, SIM, TCH` (`S` is bandit's security rules)

Each module uses a single consistent import style. Do not mix `import x` and `from x import y`
forms for the same dependency within one module.

### Tests

**Test policy: any change that adds or modifies functionality must ship with tests in the
same pull request.** Bug fixes must include a regression test that fails before the fix and
passes after it. This is enforced in review, and by the coverage gate.

- coverage must stay at or above 90% (`--cov-fail-under=90`)
- the partner conformance suite must pass: `python -m presidio_x402.conformance`

### Security-sensitive changes

This library's security controls are the product. If your change touches PII detection and
redaction, spending-policy enforcement, replay fingerprinting, audit-log chaining,
multi-party authorization, or evidence and canonicalisation code, then:

- explain the security reasoning in the PR description, not only the mechanics
- do not weaken a default. New controls are opt-in; relaxations of existing controls need
  an explicit rationale
- never re-implement cryptographic primitives — call `hashlib`, `hmac`, `secrets`, or
  `cryptography`
- canonicalisation and digest functions are byte-stability contracts. Changing their output
  for existing input is a breaking change even if no signature changes

### Public API and compatibility

The public API surface and what counts as a breaking change are defined in
[SEMVER.md](SEMVER.md). Read it before changing anything exported from
`presidio_x402.__all__`, and note that audit event shapes and exception types are part of the
contract that OEM partners depend on.

### Dependencies

New runtime dependencies are a high bar for a security library and need justification in the
PR. Prefer the standard library. Optional functionality belongs in an
`[project.optional-dependencies]` extra rather than the core dependency set.

## Local verification

Run this before opening a PR, and fix anything it reports:

```bash
cd tools
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m ruff check . \
  && .venv/bin/python -m ruff format --check . \
  && .venv/bin/python -m pytest tests/ -x -q --tb=short
```

CI runs the test suite against Python 3.10, 3.11, 3.12, and 3.13. A change must pass on all
four.

## Commit messages

Write in the imperative mood ("add replay TTL bound", not "added" or "adds"). Explain *why*
the change is being made where that is not obvious from the diff.

## Licensing and Developer Certificate of Origin (DCO)

The project is MIT licensed, and contributions are accepted under the same terms
(inbound = outbound).

To assert that you have the right to submit your contribution, every commit must
be **signed off** under the [Developer Certificate of Origin](https://developercertificate.org/)
1.1. Signing off means adding a `Signed-off-by` line to the commit message with
your real name and email:

```
Signed-off-by: Jane Developer <jane@example.com>
```

`git commit -s` adds this line for you. By signing off you certify the DCO —
in short, that you wrote the change or otherwise have the right to submit it
under the project's MIT license. Pull requests whose commits are not signed off
will be asked to amend before merge.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
