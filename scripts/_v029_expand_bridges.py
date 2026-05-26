"""v0.29 bridges.json expansion. WebFetch-verified additions only.

Run once: `python scripts/_v029_expand_bridges.py`.
Idempotent — skips entries already present via (chain, lowercased
address) key.

Sources (all WebFetched 2026-05-26):
  * Stargate: https://stargateprotocol.gitbook.io/stargate
  * Wormhole: https://wormhole.com/docs/products/reference/contract-addresses/
  * Hop:      https://github.com/hop-protocol/hop/blob/develop/packages/sdk/src/addresses/mainnet.ts
"""
import json
from pathlib import Path

PATH = Path(__file__).parent.parent / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
with open(PATH, encoding="utf-8") as f:
    data = json.load(f)

existing: set[tuple[str, str]] = set()
for e in data:
    if isinstance(e, dict) and "address" in e:
        chain = e.get("chain", "ethereum").lower()
        existing.add((chain, e["address"].lower()))
print(
    f"Pre-expansion: "
    f"{len([e for e in data if isinstance(e, dict) and 'address' in e])} entries; "
    f"{len(existing)} unique (chain, address) keys"
)


def mk(addr, name, chain, supports_to, source_url, source_doc, follow_up_url, notes=None):
    return {
        "address": addr,
        "name": name,
        "chain": chain,
        "category": "bridge",
        "source": source_doc,
        "confidence": "high",
        "supports_to_chains": supports_to,
        "follow_up_url": follow_up_url,
        "notes": notes,
        "added_at": "2026-05-26T00:00:00Z",
        "_v029_addition": True,
        "_audit_status": f"externally_verified_v029: WebFetch from {source_url}",
    }


new_entries: list[dict] = []
SG_URL = "https://stargateprotocol.gitbook.io/stargate"
WH_URL = "https://wormhole.com/docs/products/reference/contract-addresses"
HOP_URL = "https://github.com/hop-protocol/hop/blob/develop/packages/sdk/src/addresses/mainnet.ts"
sg_to = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom", "linea", "metis", "mantle", "kava"]
wh_to = ["ethereum", "solana", "bsc", "polygon", "avalanche", "fantom", "arbitrum", "optimism", "base", "celo", "moonbeam"]
hop_to = ["ethereum", "arbitrum", "optimism", "base", "polygon", "gnosis"]

stargate_data = [
    ("0x8731d54E9D02c286767d56ac03e8037C07e01e98", "Stargate: Router (Ethereum)", "ethereum"),
    ("0x150f94B44927F078737562f0fcF3C95c01Cc2376", "Stargate: RouterETH (Ethereum)", "ethereum"),
    ("0x296F55F8Fb28E498B858d0BcDA06D955B2Cb3f97", "Stargate: Bridge (Ethereum)", "ethereum"),
    ("0xeCc19E177d24551aA7ed6Bc6FE566eCa726CC8a9", "Stargate: Composer (Ethereum)", "ethereum"),
    ("0xdf0770dF86a8034b3EFEf0A1Bb3c889B8332FF56", "Stargate: USDC Pool (Ethereum)", "ethereum"),
    ("0x38EA452219524Bb87e18dE1C24D3bB59510BD783", "Stargate: USDT Pool (Ethereum)", "ethereum"),
    ("0x101816545F6bd2b1076434B54383a1E633390A2E", "Stargate: ETH Pool (Ethereum)", "ethereum"),
    ("0x0Faf1d2d3CED330824de3B8200fc8dc6E397850d", "Stargate: DAI Pool (Ethereum)", "ethereum"),
    ("0xfA0F307783AC21C39E939ACFF795e27b650F6e68", "Stargate: FRAX Pool (Ethereum)", "ethereum"),
    ("0x4a364f8c717cAAD9A442737Eb7b8A55cc6cf18D8", "Stargate: Router (BSC)", "bsc"),
    ("0x6694340fc020c5E6B96567843da2df01b2CE1eb6", "Stargate: Bridge (BSC)", "bsc"),
    ("0x9aA83081AA06AF7208Dcc7A4cB72C94d057D2cda", "Stargate: USDT Pool (BSC)", "bsc"),
    ("0x45A01E4e04F14f7A4a6702c74187c5F6222033cd", "Stargate: Router (Avalanche)", "avalanche"),
    ("0x9d1B1669c73b033DFe47ae5a0164Ab96df25B944", "Stargate: Bridge (Avalanche)", "avalanche"),
    ("0x1205f31718499dBf1fCa446663B532Ef87481fe1", "Stargate: USDC Pool (Avalanche)", "avalanche"),
    ("0x29e38769f23701A2e4A8Ef0492e19dA4604Be62c", "Stargate: USDT Pool (Avalanche)", "avalanche"),
    ("0x892785f33CdeE22A30AEF750F285E18c18040c3e", "Stargate: USDC Pool (Arbitrum)", "arbitrum"),
    ("0xB6CfcF89a7B22988bfC96632aC2A9D6daB60d641", "Stargate: USDT Pool (Arbitrum)", "arbitrum"),
    ("0x915A55e36A01285A14f05dE6e81ED9cE89772f8e", "Stargate: ETH Pool (Arbitrum)", "arbitrum"),
    ("0x352d8275AAE3e0c2404d9f68f6cEE084B5bEB3DD", "Stargate: Bridge (Arbitrum)", "arbitrum"),
    ("0xB49c4e680174E331CB0A7fF3Ab58afC9738d5F8b", "Stargate: RouterETH (Optimism)", "optimism"),
    ("0x701a95707A0290AC8B90b3719e8EE5b210360883", "Stargate: Bridge (Optimism)", "optimism"),
    ("0xDecC0c09c3B5f6e92EF4184125D5648a66E35298", "Stargate: USDC Pool (Optimism)", "optimism"),
    ("0xd22363e3762cA7339569F3d33EADe20127D5F98C", "Stargate: ETH Pool (Optimism)", "optimism"),
    ("0x165137624F1f692e69659f944BF69DE02874ee27", "Stargate: DAI Pool (Optimism)", "optimism"),
    ("0x50B6EbC2103BFEc165949CC946d739d5650d7ae4", "Stargate: RouterETH (Base)", "base"),
    ("0x28fc411f9e1c480AD312b3d9C60c22b965015c6B", "Stargate: ETH Pool (Base)", "base"),
    ("0x4c80E24119CFB836cdF0a6b53dc23F04F7e652CA", "Stargate: USDC Pool (Base)", "base"),
    ("0x9d1B1669c73b033DFe47ae5a0164Ab96df25B944", "Stargate: Bridge (Polygon)", "polygon"),
    ("0xAf5191B0De278C7286d6C7CC6ab6BB8A73bA2Cd6", "Stargate: Router (Fantom)", "fantom"),
    ("0xc647ce76ec30033aa319d472ae9f4462068f2ad7", "Stargate: USDC Pool (Fantom)", "fantom"),
    ("0x2F6F07CDcf3588944Bf4C42aC74ff24bF56e7590", "Stargate: Router (Linea)", "linea"),
    ("0x45f1A95A4D3f3836523F5c83673c797f4d4d263B", "Stargate: Bridge (Metis)", "metis"),
]

wormhole_data = [
    ("0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B", "Wormhole: Core Bridge (Ethereum)", "ethereum"),
    ("0xa5f208e072434bC67592E4C49C1B991BA79BCA46", "Wormhole: Core Bridge (Arbitrum)", "arbitrum"),
    ("0xEe91C335eab126dF5fDB3797EA9d6aD93aeC9722", "Wormhole: Core Bridge (Optimism)", "optimism"),
    ("0xbebdb6C8ddC678FfA9f8748f85C815C556Dd8ac6", "Wormhole: Core Bridge (Base)", "base"),
    ("0x7A4B5a56256163F07b2C80A7cA55aBE66c4ec4d7", "Wormhole: Core Bridge (Polygon)", "polygon"),
    ("0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B", "Wormhole: Core Bridge (BSC)", "bsc"),
    ("0x54a8e5f9c4CbA08F9943965859F6c34eAF03E26c", "Wormhole: Core Bridge (Avalanche)", "avalanche"),
    ("0x126783A6Cb203a3E35344528B26ca3a0489a1485", "Wormhole: Core Bridge (Fantom)", "fantom"),
    ("0x3ee18B2214AFF97000D974cf647E7C347E8fa585", "Wormhole: Portal TokenBridge (Ethereum)", "ethereum"),
    ("0x5a58505a96D1dbf8dF91cB21B54419FC36e93fdE", "Wormhole: Portal TokenBridge (Polygon)", "polygon"),
    ("0xB6F6D86a8f9879A9c87f643768d9efc38c1Da6E7", "Wormhole: Portal TokenBridge (BSC)", "bsc"),
    ("0x0e082F06FF657D94310cB8cE8B0D9a04541d8052", "Wormhole: Portal TokenBridge (Avalanche)", "avalanche"),
    ("0x7C9Fc5741288cDFdD83CeB07f3ea7e22618D79D2", "Wormhole: Portal TokenBridge (Fantom)", "fantom"),
    ("0x796Dff6D74F3E27060B71255Fe517BFb23C93eed", "Wormhole: Portal TokenBridge (Celo)", "celo"),
]

hop_data = [
    ("0x0e0E3d2C5c292161999474247956EF542caBF8dd", "Hop: USDC L2 Bridge (Arbitrum)", "arbitrum"),
    ("0xa81D244A1814468C734E5b4101F7b9c0c577a8fC", "Hop: USDC L2 Bridge (Optimism)", "optimism"),
    ("0x46ae9BaB8CEA96610807a275EBD36f8e916b5C61", "Hop: USDC L2 Bridge (Base)", "base"),
    ("0x25D8039bB044dC227f741a9e381CA4cEAE2E6aE8", "Hop: USDC L2 Bridge (Polygon)", "polygon"),
    ("0x72209Fe68386b37A40d6bCA04f78356fd342491f", "Hop: USDT L2 Bridge (Arbitrum)", "arbitrum"),
    ("0x6c9a1ACF73bd85463A46B0AFc076FBdf602b690B", "Hop: USDT L2 Bridge (Polygon)", "polygon"),
    ("0x7aC115536FE3A185100B2c4DE4cb328bf3A58Ba6", "Hop: DAI L2 Bridge (Arbitrum)", "arbitrum"),
    ("0x7191061D5d4C60f598214cC6913502184BAddf18", "Hop: DAI L2 Bridge (Optimism)", "optimism"),
    ("0xEcf268Be00308980B5b3fcd0975D47C4C8e1382a", "Hop: DAI L2 Bridge (Polygon)", "polygon"),
    ("0x3749C4f034022c39ecafFaBA182555d4508caCCC", "Hop: ETH L2 Bridge (Arbitrum)", "arbitrum"),
    ("0x83f6244Bd87662118d96D9a6D44f09dffF14b30E", "Hop: ETH L2 Bridge (Optimism)", "optimism"),
    ("0x3666f603Cc164936C1b87e207F36BEBa4AC5f18a", "Hop: ETH L2 Bridge (Base)", "base"),
    ("0xb98454270065A31D71Bf635F6F7Ee6A518dFb849", "Hop: ETH L2 Bridge (Polygon)", "polygon"),
    ("0x553bC791D746767166fA3888432038193cEED5E2", "Hop: MATIC L2 Bridge (Polygon)", "polygon"),
]


def maybe_add(addr, name, chain, supports_to, source_url, source_doc, follow_up_url):
    key = (chain, addr.lower())
    if key in existing:
        return False
    existing.add(key)
    new_entries.append(mk(addr, name, chain, supports_to, source_url, source_doc, follow_up_url))
    return True


for addr, name, chain in stargate_data:
    maybe_add(addr, name, chain, sg_to, SG_URL, "stargate_docs", SG_URL)

for addr, name, chain in wormhole_data:
    maybe_add(addr, name, chain, wh_to, WH_URL, "wormhole_docs", "https://wormholescan.io")

for addr, name, chain in hop_data:
    maybe_add(addr, name, chain, hop_to, HOP_URL, "hop_docs", "https://explorer.hop.exchange")

print(f"\nNew entries to add: {len(new_entries)}")
data.extend(new_entries)
total_with_addr = len([e for e in data if isinstance(e, dict) and "address" in e])
print(f"Post-expansion total: {total_with_addr} entries")

with open(PATH, "w", encoding="utf-8", newline="\n") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("Written.")
