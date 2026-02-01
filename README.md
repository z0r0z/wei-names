<p align="center">
  <img src="./wns-icon.svg" alt="WNS" width="64" height="64">
</p>

# Wei Name Service (WNS)

A simple namespace on Ethereum named after the smallest unit of ether.

**Contract:** `0x0000000000696760E15f265e828DB644A0c242EB` (Ethereum Mainnet)

**Gateway:** `wei.domains` - resolves `name.wei.domains` to IPFS content

**Dapp:** `wei.domains` (hosted via IPFS)

---

## Overview

WNS provides `.wei` names as NFTs (ERC-721). Names can:
- Resolve to an Ethereum address (receive payments)
- Host a website via IPFS contenthash
- Have unlimited free subdomains
- Display as your wallet's identity (reverse resolution)

## Registration

WNS uses a **commit-reveal** pattern to prevent frontrunning (similar to ENS):

1. **Commit** - Submit `keccak256(label, owner, secret)` and wait 60 seconds
2. **Reveal** - Submit the actual name + secret + pay fee
3. Commitment expires after 24 hours

```
Fee (per year by byte length):
  1 byte:  0.5 ETH
  2 bytes: 0.1 ETH
  3 bytes: 0.05 ETH
  4 bytes: 0.01 ETH
  5+ bytes: 0.0005 ETH

Duration: 1 year, renewable
```

## Token ID Computation

Token IDs use namehash, similar to ENS:

```
WEI_NODE = keccak256("wei")
       = 0xa82820059d5df798546bcc2985157a77c3eef25eba9ba01899927333efacbd6f

tokenId = keccak256(WEI_NODE || keccak256(label))
```

For subdomains, recursively hash parent nodes.

**Example (JavaScript):**
```javascript
const WEI_NODE = '0xa82820059d5df798546bcc2985157a77c3eef25eba9ba01899927333efacbd6f';

function computeTokenId(label) {
  const labelHash = ethers.keccak256(ethers.toUtf8Bytes(label));
  return BigInt(ethers.keccak256(ethers.concat([WEI_NODE, labelHash])));
}
```

---

## Normalization & Display

### Background

Unicode includes visually similar characters across scripts (e.g., Latin `a` vs Cyrillic `а`). This is a universal challenge for any naming system supporting international characters.

Like ENS and other naming systems, WNS stores **raw bytes on-chain** and delegates normalization to the client/frontend layer. This is the established pattern in the ecosystem.

### Why Client-Side Normalization

1. **Future-proof** - Normalization standards evolve. ENSIP-15 replaced ENSIP-1, Unicode itself updates yearly. On-chain rules would be frozen forever or require expensive upgrades.

2. **Ecosystem alignment** - ENS, DNS, and other systems handle normalization at the application layer. Wallets and dapps already implement these checks.

3. **International support** - Overly restrictive on-chain validation could block legitimate international names. Better to let standards bodies (Unicode, ENSIP) define what's valid.

4. **Simplicity** - Contract stays minimal, gas-efficient, and auditable.

### Frontend Responsibility

Frontends (dapps, wallets, explorers) SHOULD:

1. **Normalize input** using [ENSIP-15](https://docs.ens.domains/ensip/15/) via `@adraffy/ens-normalize`
2. **Warn users** about non-normalized names
3. **Verify before purchase** on secondary markets

**Example:**
```javascript
import { ens_normalize } from '@adraffy/ens-normalize';

function normalizeLabel(label) {
  try {
    const normalized = ens_normalize(label);
    if (normalized.includes('.')) return null; // No dots in labels
    return normalized;
  } catch (e) {
    return null; // Invalid (confusables, invisible chars, etc.)
  }
}
```

### Verification Tool

The official dapp includes a "verify name" helper:
- Enter a token ID (from OpenSea URL, etc.)
- See the actual on-chain name and byte representation
- Check ENSIP-15 normalization status
- Compare against an expected name

Useful for secondary market purchases or inspecting unfamiliar names.

---

## Contract Interface

### Read Functions

```solidity
// Check availability
function isAvailable(string label, uint256 parentId) view returns (bool)

// Get registration fee (by byte length)
function getFee(uint256 length) view returns (uint256)

// Get premium for recently expired names
function getPremium(uint256 tokenId) view returns (uint256)

// Resolve name to address
function resolve(uint256 tokenId) view returns (address)

// Reverse resolve address to name
function reverseResolve(address addr) view returns (string)

// Get contenthash (IPFS, etc.)
function contenthash(uint256 tokenId) view returns (bytes)

// Get text record
function text(uint256 tokenId, string key) view returns (string)

// Get full name (e.g., "sub.name.wei")
function getFullName(uint256 tokenId) view returns (string)

// Compute token ID from name
function computeId(string fullName) pure returns (uint256)
```

### Write Functions

```solidity
// Commit-reveal registration
function commit(bytes32 commitment)
function reveal(string label, bytes32 secret) payable returns (uint256)

// Set resolver address (where payments go)
function setAddr(uint256 tokenId, address addr)

// Set contenthash (for IPFS websites)
function setContenthash(uint256 tokenId, bytes hash)

// Set text record
function setText(uint256 tokenId, string key, string value)

// Set as primary name (reverse resolution)
function setPrimaryName(uint256 tokenId)

// Register subdomain (free, if you own parent)
function registerSubdomain(string label, uint256 parentId) returns (uint256)

// Renew registration
function renew(uint256 tokenId) payable

// Standard ERC-721 transfer
function transferFrom(address from, address to, uint256 tokenId)
```

---

## IPFS Contenthash

To host a website at `name.wei.domains`:

1. Pin your site to IPFS (Pinata, web3.storage, etc.)
2. Get the CID (`Qm...` or `baf...`)
3. Call `setContenthash(tokenId, encodedHash)`

**Encoding:**
```javascript
// Contenthash = 0xe3 (IPFS namespace) + CID bytes
function encodeContenthash(cid) {
  let cidBytes;
  if (cid.startsWith('Qm')) {
    // CIDv0 -> CIDv1
    cidBytes = new Uint8Array([0x01, 0x70, ...base58Decode(cid)]);
  } else if (cid.startsWith('baf')) {
    // CIDv1 base32
    cidBytes = base32Decode(cid.slice(1));
  }
  return ethers.concat(['0xe3', cidBytes]);
}
```

---

## Gateway (wei.domains)

The Cloudflare Worker at `wei.domains`:

1. Extracts name from subdomain (`name.wei.domains`)
2. Queries contract for contenthash
3. Decodes CID and fetches from IPFS
4. Serves content with caching

**Root domain** (`wei.domains`) resolves to `wns.wei` (the official dapp).

---

## Multicall

For efficient batching, use Multicall3:

```javascript
const MULTICALL3 = '0xcA11bde05977b3631167028862bE2a173976CA11';

const results = await multicall.aggregate3([
  { target: WNS, callData: encodeFunctionData('isAvailable', [name, 0]) },
  { target: WNS, callData: encodeFunctionData('getFee', [byteLength]) },
  { target: WNS, callData: encodeFunctionData('getPremium', [tokenId]) }
]);
```

---

## Best Practices for Integrators

1. **Normalize input** with ENSIP-15 before registration (same as ENS)
2. **Use the verification tool** or compute expected token IDs when buying on secondary markets
3. **Display normalization warnings** for names that don't pass ENSIP-15
4. **Link to the official dapp** (`wei.domains/#name`) for name lookups

---

## Links

- **Dapp:** https://wei.domains
- **Contract:** https://etherscan.io/address/0x0000000000696760E15f265e828DB644A0c242EB
- **OpenSea:** https://opensea.io/collection/wei-name-service
- **ENSIP-15:** https://docs.ens.domains/ensip/15/
- **ens-normalize:** https://github.com/adraffy/ens-normalize.js
