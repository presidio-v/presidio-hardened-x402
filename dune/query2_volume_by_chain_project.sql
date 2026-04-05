-- Query 2 — Volume sanity check by chain and project
-- Run in Dune Analytics (Trino SQL)
-- Purpose: Confirm tx counts, date ranges, and project breakdown
--          before committing to a deeper data collection strategy.
--
-- Source: evms.transactions + query_6054244 (facilitator address→project map)
-- Scope:  All EVM chains, from 2025-10-01 (protocol launch)

WITH x402f AS (
    SELECT address, project, blockchain
    FROM query_6054244   -- hashed_official facilitator address list
)
SELECT
    xf.blockchain,
    xf.project,
    COUNT(*)                                   AS tx_count,
    MIN(et.block_time)                         AS first_tx,
    MAX(et.block_time)                         AS last_tx,
    COUNT(DISTINCT DATE_TRUNC('day', et.block_time)) AS active_days,
    ROUND(COUNT(*) * 1.0 / NULLIF(
        COUNT(DISTINCT DATE_TRUNC('day', et.block_time)), 0
    ), 1)                                      AS avg_tx_per_day
FROM evms.transactions et
INNER JOIN x402f xf
    ON xf.address = et."from"
   AND xf.blockchain = et.blockchain
   AND et.success = TRUE
WHERE et.block_time >= CAST('2025-10-01' AS TIMESTAMP)
GROUP BY 1, 2
ORDER BY tx_count DESC
LIMIT 100
