# Project Governance

`presidio-hardened-x402` is developed and maintained by **PRESIDIO**
(<https://presidio-group.eu>) and published under the `presidio-v` GitHub
organisation. This document describes how the project is governed, who holds
which responsibilities, and how the project continues to function if any single
individual becomes unavailable.

## Governance model

The project follows a **maintainer-led, single-steward** model. PRESIDIO is the
steward organisation: it owns the repository, the release infrastructure, and
the published artefacts, and it sets the security bar the project is held to.

Day-to-day technical decisions are made by the maintainers by rough consensus:

- **Ordinary changes** (bug fixes, tests, documentation, dependency floors) are
  decided by the reviewing maintainer on the pull request.
- **Security-relevant changes** (anything touching PII detection, spending-policy
  enforcement, replay fingerprinting, audit-log chaining, multi-party
  authorization, or evidence and canonicalisation code) require an explicit
  security rationale in the pull request and must not weaken an existing default.
  See [CONTRIBUTING.md](CONTRIBUTING.md#security-sensitive-changes).
- **Public-API and compatibility changes** are governed by [SEMVER.md](SEMVER.md);
  a breaking change requires a major/minor bump per the documented policy.
- **Disagreements** that cannot be resolved on the pull request are escalated to
  the steward organisation (PRESIDIO), whose decision is final.

There is no pay-to-play influence: contribution weight is earned through review
history and sustained, high-quality contribution, not funding.

## Roles and responsibilities

| Role | Held by | Responsibilities |
|---|---|---|
| **Steward organisation** | PRESIDIO (`presidio-v` GitHub org) | Owns the repository and release infrastructure; holds and can recover all release credentials; final escalation authority; ensures continuity (see below). |
| **Maintainer** | PRESIDIO engineering | Reviews and merges pull requests; enforces the test, style, and security bars; cuts releases; triages issues; is the point of accountability for the codebase. |
| **Security contact** | PRESIDIO security | Receives and triages private vulnerability reports (see [SECURITY.md](SECURITY.md)); coordinates fixes, advisories, and reporter credit. Reachable at `security@presidio-group.eu` and via GitHub Security Advisories. |
| **Release manager** | PRESIDIO engineering | Owns the signed-tag → Trusted-Publishing release flow; verifies provenance and SBOM attach on each release. |
| **Contributor** | Anyone | Opens issues and pull requests under [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). |

Roles are held by function within PRESIDIO rather than being tied to one named
individual, so responsibilities transfer without a change to this document.

## Becoming a maintainer

A contributor with a sustained track record of merged, high-quality changes —
particularly to the security-sensitive modules — may be invited by the steward
organisation to become a maintainer. Maintainership is granted by PRESIDIO and
recorded by adding the person to the `presidio-v` organisation with the
appropriate repository role.

## Project continuity

The project is structured so that it continues to function — issues can be
triaged and closed, contributions can be reviewed and accepted, and new versions
can be released — within one week even if any single individual becomes
unavailable. This is a property of the **organisation**, not of any one person:

- **Repository ownership** is held by the `presidio-v` GitHub organisation, not
  by a personal account. Organisation owners can grant repository and release
  access to another member at any time.
- **Release credentials are not personal.** Publishing to PyPI uses GitHub
  **Trusted Publishing (OIDC)** bound to the `presidio-v/presidio-hardened-x402`
  repository and a founder-gated `release` environment — there is no personal
  API token that dies with an individual. The release signing key is held in the
  organisation's password manager (custody ultimately with PRESIDIO's
  leadership), not solely on any one contributor's machine, so it is recoverable.
- **The release process is fully documented** — see the signed-tag → Trusted
  Publishing flow in [SECURITY.md](SECURITY.md#supply-chain-provenance-slsa-build-l3)
  and the `.github/workflows/publish.yml` workflow — so any authorised PRESIDIO
  engineer can cut a release by following it.
- **PRESIDIO is a staffed organisation** with more than one person able to assume
  the maintainer, security-contact, and release-manager roles above.

The project's bus factor is therefore backed by the steward organisation rather
than a lone maintainer.
