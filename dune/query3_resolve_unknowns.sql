-- Query 3 — Resolve unknown Base wallet addresses to project names
-- Run in Dune (fast: tiny lookup against query_6054244)

SELECT CAST(address AS varchar) AS address, project, blockchain
FROM query_6054244
WHERE blockchain = 'base'
  AND LOWER(CAST(address AS varchar)) IN (
    '0xd97c12726dcf994797c981d31cfb243d231189fb',
    '0x0168f80e035ea68b191faf9bfc12778c87d92008',
    '0x97d38aa5de015245dcca76305b53abe6da25f6a5',
    '0x90d5e567017f6c696f1916f4365dd79985fce50f',
    '0x88e13d4c764a6c840ce722a0a3765f55a85b327e',
    '0x76eee8f0acabd6b49f1cc4e9656a0c8892f3332e',
    '0xc19829b32324f116ee7f80d193f99e445968499a',
    '0x5e437bee4321db862ac57085ea5eb97199c0ccc5',
    '0x65058cf664d0d07f68b663b0d4b4f12a5e331a38',
    '0x87af99356d774312b73018b3b6562e1ae0e018c9'
  )
ORDER BY address
