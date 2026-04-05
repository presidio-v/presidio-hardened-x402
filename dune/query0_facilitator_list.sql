-- Query 0 — Inspect facilitator address list
-- Run in Dune Analytics (Trino SQL)
-- Purpose: Understand which facilitator wallets exist, how many projects,
--          which chains — needed before all other queries.
--
-- Source: query_6054244 (hashed_official EVM facilitator address→project map)

SELECT
    blockchain,
    project,
    COUNT(*)          AS wallet_count,
    SLICE(ARRAY_AGG(address), 1, 3) AS sample_addresses
FROM query_6054244
GROUP BY 1, 2
ORDER BY wallet_count DESC
