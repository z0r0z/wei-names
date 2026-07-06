# ConvictionVeto — CREATE3 deploy package

Peripheral "decentralized no" layer for WeiDAO. Deployed via **canonical CreateX** so the address is
mined (vanity) and independent of the initcode. **Inert on deploy** — does nothing until it is assigned
the `veto.dao.wei` role (a separate, later step).

## Parameters

| Field | Value |
|---|---|
| Deployer EOA (signs) | `0x1C0Aa8cCD568d90d61659F060D1bFb1e6f855A20` |
| CreateX (canonical) | `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed` |
| Constructor arg `dao_` | `0x00000007988A79d16cf76B5dc4cF54dc3Af24936` (live WeiDAO) |
| **Salt** (sender-bound, byte 20 = `0x00`) | `0x1c0aa8ccd568d90d61659f060d1bfb1e6f855a20009941d8f734fa232b5bdfd0` |
| **Predicted address** (3 zero bytes) | `0x0000005260725eEE99704957218d4045a50C2051` |
| initCode | `ops/cv_initcode.hex` (keccak `0xc6068562db0e779eadddc8dd532e708f7e63871644cf7e8893bd838a92cd0e70`) |
| value | `0` |

The salt's first 20 bytes are the deployer, so **only that EOA** can consume it (no front-run). Change
the deployer ⇒ re-mine the salt.

## Deploy (call CreateX.deployCreate3 from the deployer EOA)

**Option A — cast:**
```bash
cast send 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed \
  "deployCreate3(bytes32,bytes)" \
  0x1c0aa8ccd568d90d61659f060d1bfb1e6f855a20009941d8f734fa232b5bdfd0 \
  $(cat ops/cv_initcode.hex) \
  --rpc-url <RPC> --account <keystore>   # or --ledger
```

**Option B — raw calldata** (paste into wallet: to = CreateX, value = 0):
`ops/cv_deploycreate3_calldata.hex` (selector `0x9c36a286`).

## Verify after deploy

```bash
forge verify-contract 0x0000005260725eEE99704957218d4045a50C2051 \
  src/ConvictionVeto.sol:ConvictionVeto \
  --constructor-args $(cast abi-encode "c(address)" 0x00000007988A79d16cf76B5dc4cF54dc3Af24936) \
  --etherscan-api-key <KEY> --watch
```

Sanity: `cast call <addr> "dao()(address)"` → live DAO; `"nft()(address)"` → live NameNFT.

## Rehearsal

`RUN_FORK_SIM=true forge test --match-contract ConvictionVetoDeploySim -vv` deploys the exact initcode
via the real CreateX on a mainnet fork and asserts address + wiring. (Passes.)
