-- Query 2b — Volume on Polygon only
-- Uses polygon.transactions (chain-specific table)

WITH x402f AS (
    SELECT address
    FROM query_6054244
    WHERE blockchain = 'polygon'
)
SELECT
    f.address                                              AS facilitator_wallet,
    COUNT(*)                                               AS tx_count,
    MIN(t.block_time)                                      AS first_tx,
    MAX(t.block_time)                                      AS last_tx,
    COUNT(DISTINCT DATE_TRUNC('day', t.block_time))        AS active_days,
    ROUND(COUNT(*) * 1.0 /
        NULLIF(COUNT(DISTINCT DATE_TRUNC('day', t.block_time)), 0), 1) AS avg_tx_per_day
FROM polygon.transactions t
INNER JOIN x402f f
    ON f.address = t."from"
WHERE t.block_time >= CAST('2025-10-01' AS TIMESTAMP)
  AND t.success = TRUE
GROUP BY 1
ORDER BY tx_count DESC
