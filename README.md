# T4 Diamond PoCs — Morpheus hunt #27

Foundry PoCs against the deployed LumerinDiamond on Base mainnet (fork).

- Target: `0x6aBE1d282f72B474E54527D93b979A4f64d3030a`
- Fork block: **58427268** (verified 2026-11-17; live facet set matches Appendix A exactly)
- Facets tested (live, via `facets()`): ProviderRegistry `0xE30279b79392AEfF7fDf1883C23d52eBA9D88A75`,
  ModelRegistry `0xb7994dE339AEe515C9b2792831CD83f3C9D8df87`,
  Marketplace `0x5B660aB78f3AC743953F9E68630A2D66e7b45F64`,
  Delegation `0x345B8B23c38F70f1d77560C60493Bb583f012Cb0`,
  SessionRouter `0x3a3952f0E57b343F00b31F7dA039eF16389B7260`
- Source: Morpheus-Lumerin-Node `ba14d2fd2b15a1d24d430936204751a3e648526c` (Release v7.19.0)

## Run

```sh
BASE_RPC_URL=https://mainnet.base.org forge test
```

No other setup. Tests are local-only (mainnet fork), use no privileged
accounts, and assert the loss / broken invariant in each test.

## Tests

- `test/T4-01-ApprovalHijack.t.sol` — CONFIRMED (Medium): provider session
  approval not bound to a user; attacker front-runs a victim's approval,
  victim locked out, funding account pays provider ~28 MOR (~$19.60).
- `test/T4-02-ClaimUnderflow.t.sol` — CONFIRMED transient revert, NOT
  submittable: `claimForProvider` underflows after an undisputed early close;
  no funds lost (provider already paid in full); recovers next day.
- `test/T4-03-WildcardDelegation.t.sol` — mechanics confirmation, NOT a
  finding: delegate.xyz wildcard (rights=0) delegations satisfy the diamond's
  per-rule check; requires the victim to delegate to the attacker.
