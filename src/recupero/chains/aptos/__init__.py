"""Aptos mainnet chain adapter (roadmap-v4: Aptos live transfer coverage).

The Move-VM address codec (``chains/move_address.py``) shipped earlier; this
package adds the live transfer-fetching layer (``client`` + ``adapter``) built on
the public, keyless Aptos Indexer GraphQL (``fungible_asset_activities``), whose
shapes were verified against real responses from
``api.mainnet.aptoslabs.com/v1/graphql``.
"""
