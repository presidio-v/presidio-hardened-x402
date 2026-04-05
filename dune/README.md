# Dune Analytics Query Set — presidio-hardened-x402

Trino SQL queries used for the live x402 ecosystem characterisation reported in:

> Stantchev, V. (2026). *Hardening x402: Privacy-Preserving Agentic Payments via
> Pre-Execution Metadata Filtering.* IEEE Transactions on Information Forensics and
> Security (under review).

These queries produce the ecosystem statistics cited in the paper: 20 projects,
96 facilitator wallets, 11 chains, ≥79 million transactions as of Q1 2026.

---

## Prerequisites

- A [Dune Analytics](https://dune.com) account (free tier is sufficient for all queries)
- Access to the hashed official facilitator address list (`query_6054244`), a public
  Dune community query mapping facilitator wallet addresses to x402 projects and chains

---

## Query Index

| File | Purpose | Engine |
|---|---|---|
| `query0_facilitator_list.sql` | Enumerate all facilitator wallets: project names, chains, wallet counts | Any |
| `query2_volume_by_chain_project.sql` | Transaction counts and date ranges across all EVM chains | Large (may be slow) |
| `query2a_volume_base.sql` | Transaction volume on Base L2 only — run this first | Medium |
| `query2b_volume_polygon.sql` | Transaction volume on Polygon only | Medium |
| `query2c_volume_other_chains.sql` | Transaction volume on all remaining chains | Large / per-chain fallback |
| `query3_resolve_unknowns.sql` | Resolve specific Base wallet addresses to project names | Any |

---

## Recommended Run Order

1. **`query0_facilitator_list.sql`** — get the lay of the land: how many wallets, which
   projects, which chains. Use this to understand the scope before running volume queries.

2. **`query2a_volume_base.sql`** then **`query2b_volume_polygon.sql`** — Base and Polygon
   account for the large majority of volume. Run these on the medium engine; they use
   chain-specific tables (`base.transactions`, `polygon.transactions`) and are much faster
   than the cross-chain query.

3. **`query2c_volume_other_chains.sql`** — covers the remaining 9 chains. Uses
   `evms.transactions` which is slower; a per-chain fallback is included in the file
   comments if the query times out.

4. **`query2_volume_by_chain_project.sql`** — optional cross-chain aggregate for a
   single summary table. May time out on the free tier; use the chain-specific queries
   (2a/2b/2c) and aggregate results manually if needed.

5. **`query3_resolve_unknowns.sql`** — run after 2a if any Base wallets are not resolved
   to a project name by `query_6054244`. Edit the `IN (...)` list with the unresolved
   addresses from your query2a output.

---

## Scope

All queries filter `block_time >= '2025-10-01'` (x402 protocol launch) and
`success = TRUE`.

---

## Reproducibility Note

Dune Analytics query results reflect the blockchain state at the time of execution.
The figures cited in the paper (≥79M transactions as of Q1 2026) were obtained by
running these queries in March 2026. Re-running the queries will return higher counts
as the ecosystem grows.
