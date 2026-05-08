-- One-time cleanup of watchlist rows polluted by the pre-fix dormant
-- detector + watchlist populator. The dormant detector used to surface
-- contract addresses (Uniswap V4 PoolManager, Across SpokePool, etc.)
-- as candidates with is_freezeable=true, and the watchlist populator
-- ran the same data in. The nightly watchlist monitor would then
-- query stablecoin balances at those public-infrastructure addresses
-- and surface them as "freezable wallets with $97M USDC" alerts —
-- false positives that would obscure real perp signals.
--
-- This migration:
--   1. Marks every watchlist row whose address looks like a known
--      protocol contract (Uniswap V4, Binance hot wallets, etc.) as
--      is_freezeable=false.
--   2. More generally, tags any watchlist row whose label_category is
--      defi_protocol/exchange_hot_wallet/exchange_deposit/bridge/mixer
--      as is_freezeable=false.
--
-- The fix in worker/watchlist.py prevents this from happening on new
-- investigations; this migration heals the existing rows so the
-- nightly monitor doesn't keep alerting on them.
--
-- Idempotent: re-running just no-ops on already-corrected rows.

BEGIN;

-- Categorical fix: any service-labeled address shouldn't be
-- is_freezeable. The new populator already enforces this.
UPDATE public.watchlist
   SET is_freezeable = FALSE
 WHERE is_freezeable = TRUE
   AND label_category IN (
       'exchange_deposit',
       'exchange_hot_wallet',
       'bridge',
       'mixer',
       'defi_protocol',
       'staking'
   );

-- Specific known contract addresses that surfaced in early smoke runs
-- but weren't labeled in our seeds. These are well-known public
-- infrastructure contracts whose balances are not perpetrator funds.
UPDATE public.watchlist
   SET is_freezeable = FALSE,
       notes = COALESCE(notes, '') ||
               CASE WHEN notes IS NULL THEN '' ELSE ' | ' END ||
               'cleanup-002: known contract address, not perp funds'
 WHERE is_freezeable = TRUE
   AND LOWER(address) IN (
       LOWER('0x000000000004444c5dc75cB358380D2e3dE08A90'),  -- Uniswap V4 PoolManager
       LOWER('0x881D40237659C251811CEC9c364ef91dC08D300C'),  -- Binance Hot Wallet 14
       LOWER('0xeF4fB24aD0916217251F553c0596F8Edc630EB66'),  -- deBridge DLN Source
       LOWER('0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5'),  -- Across V3 SpokePool
       LOWER('0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1'),  -- Lido stETH (staking, non-custodial)
       LOWER('0xe4b627559cC6a2D9873F2b9263533FfA940D4Ea6')
   );

-- Surface the cleanup count for the operator.
DO $$
DECLARE
    n INT;
BEGIN
    SELECT COUNT(*) INTO n FROM public.watchlist
     WHERE is_freezeable = FALSE
       AND notes LIKE '%cleanup-002%';
    RAISE NOTICE 'cleanup-002: marked % addresses as not-freezable by explicit-list rule', n;
END $$;

COMMIT;
