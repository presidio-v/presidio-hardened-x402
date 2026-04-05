-- Query 2c — Volume on all other chains (excluding base and polygon)
-- Still uses evms.transactions but the facilitator wallet list for these chains
-- is tiny (< 15 wallets total) so the join filters aggressively.
-- If this still times out, run one chain at a time using the VALUES list below.

WITH x402f AS (
    SELECT address, blockchain
    FROM query_6054244
    WHERE blockchain NOT IN ('base', 'polygon')
)
SELECT
    xf.blockchain,
    xf.address                                             AS facilitator_wallet,
    COUNT(*)                                               AS tx_count,
    MIN(t.block_time)                                      AS first_tx,
    MAX(t.block_time)                                      AS last_tx,
    COUNT(DISTINCT DATE_TRUNC('day', t.block_time))        AS active_days
FROM evms.transactions t
INNER JOIN x402f xf
    ON xf.address = t."from"
   AND xf.blockchain = t.blockchain
WHERE t.block_time >= CAST('2025-10-01' AS TIMESTAMP)
  AND t.success = TRUE
GROUP BY 1, 2
ORDER BY tx_count DESC

-- Fallback: if above times out, comment it out and run this for each chain
-- individually (replace 'bnb' with 'avalanche_c', 'arbitrum', 'sei', etc.):
--
-- SELECT COUNT(*) AS tx_count, MIN(block_time) AS first_tx, MAX(block_time) AS last_tx
-- FROM bnb.transactions
-- WHERE "from" IN (
--     SELECT address FROM query_6054244 WHERE blockchain = 'bnb'
-- )
-- AND block_time >= CAST('2025-10-01' AS TIMESTAMP)
-- AND success = TRUE
