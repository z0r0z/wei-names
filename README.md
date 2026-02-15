<p align="center">
  <img src="./wns-icon.svg" alt="WNS" width="64" height="64">
</p>

# Wei Name Service (WNS)

A simple namespace on Ethereum named after the smallest unit of ether.

**Contract:** `0x0000000000696760E15f265e828DB644A0c242EB` (Ethereum Mainnet)

**Subdomain Registrar:** `0x0000000000DD72Ef1DF17f527E719AEE5ef71E64`

**Gateway:** `wei.domains` - resolves `name.wei.domains` to IPFS content

**Dapp:** `wei.domains` (hosted via IPFS)

---

## Overview

WNS provides `.wei` names as NFTs (ERC-721). Names can:
- Resolve to an Ethereum address (receive payments)
- Host a website via IPFS contenthash
- Have unlimited free subdomains
- Store multi-coin addresses and text records (ENS-compatible resolver)
- Display as your wallet's identity (reverse resolution)

The contract is a single, non-upgradeable Solidity file (`NameNFT.sol`) that combines ERC-721 ownership, registration logic, and resolver functionality.

- **Solidity:** `^0.8.30`
- **License:** MIT

---

## Architecture

### Inheritance

```
NameNFT
  ├── ERC721        (solady)   — gas-optimized NFT
  ├── Ownable       (solady)   — admin access control
  └── ReentrancyGuard (soledge) — reentrancy protection
```

### Token ID = Namehash

Token IDs are computed as `uint256(namehash)`, following the ENS namehash algorithm (EIP-137).

```
namehash("") = bytes32(0)
namehash("wei") = keccak256(abi.encodePacked(namehash(""), keccak256("wei")))
namehash("alice.wei") = keccak256(abi.encodePacked(namehash("wei"), keccak256("alice")))
namehash("sub.alice.wei") = keccak256(abi.encodePacked(namehash("alice.wei"), keccak256("sub")))
```

The precomputed constant:
```
WEI_NODE = namehash("wei")
         = keccak256(abi.encodePacked(bytes32(0), keccak256("wei")))
         = 0xa82820059d5df798546bcc2985157a77c3eef25eba9ba01899927333efacbd6f
```

**JavaScript example:**
```javascript
import { ethers } from 'ethers';

const WEI_NODE = '0xa82820059d5df798546bcc2985157a77c3eef25eba9ba01899927333efacbd6f';

function computeTokenId(label) {
  const labelHash = ethers.keccak256(ethers.toUtf8Bytes(label));
  return BigInt(ethers.keccak256(ethers.concat([WEI_NODE, labelHash])));
}

function computeSubdomainId(label, parentId) {
  const parentNode = ethers.zeroPadValue(ethers.toBeHex(parentId), 32);
  const labelHash = ethers.keccak256(ethers.toUtf8Bytes(label));
  return BigInt(ethers.keccak256(ethers.concat([parentNode, labelHash])));
}
```

---

## Constants

| Constant | Value | Description |
|---|---|---|
| `WEI_NODE` | `0xa828...bd6f` | Namehash of "wei" TLD |
| `MAX_LABEL_LENGTH` | 255 bytes | Maximum label byte length |
| `MIN_LABEL_LENGTH` | 1 byte | Minimum label byte length |
| `MIN_COMMITMENT_AGE` | 60 seconds | Minimum wait before reveal |
| `MAX_COMMITMENT_AGE` | 86400 seconds (24h) | Commitment expiration |
| `REGISTRATION_PERIOD` | 365 days | Duration of one registration |
| `GRACE_PERIOD` | 90 days | Post-expiry renewal window |
| `MAX_SUBDOMAIN_DEPTH` | 10 | Maximum nesting of subdomains |
| `COIN_TYPE_ETH` | 60 | SLIP-44 coin type for ETH |
| `MAX_PREMIUM_CAP` | 10,000 ETH | Admin cap on premium setting |
| `MAX_DECAY_PERIOD` | 3,650 days | Admin cap on decay period setting |
| `DEFAULT_FEE` | 0.001 ETH | Initial default registration fee |

---

## Constructor

```solidity
constructor() payable {
    _initializeOwner(tx.origin);
    defaultFee = DEFAULT_FEE;       // 0.001 ether
    maxPremium = 100 ether;
    premiumDecayPeriod = 21 days;
}
```

**Note:** Owner is set to `tx.origin`, not `msg.sender`. This is intentional for deployment via `CREATE2` factory patterns where `msg.sender` would be the factory contract. The owner controls fee settings and ETH withdrawal.

---

## Name Lifecycle

### 1. Registration (Commit-Reveal)

A two-step commit-reveal pattern prevents frontrunning:

1. **Commit** — Submit `keccak256(abi.encode(normalizedLabel, owner, secret))` on-chain. The commitment uses the *normalized* label bytes (ASCII lowercased), not the raw input.
2. **Wait** — At least 60 seconds (`MIN_COMMITMENT_AGE`).
3. **Reveal** — Submit the label, secret, and payment. The commitment must be no older than 24 hours (`MAX_COMMITMENT_AGE`).

The commitment is deleted after a successful reveal. An expired commitment (>24h) can be overwritten by a new `commit()`.

**Off-chain commitment computation:**
```javascript
// IMPORTANT: normalize the label the same way the contract does (lowercase ASCII)
const normalized = label.toLowerCase(); // for ASCII-only labels
const commitment = ethers.keccak256(
  ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes', 'address', 'bytes32'],
    [ethers.toUtf8Bytes(normalized), ownerAddress, secret]
  )
);
```

### 2. Active Period

- Registration lasts **365 days** from the time of reveal.
- The name is **active** while `block.timestamp <= expiresAt`.
- While active: transfers, resolver writes, and resolution all work.

### 3. Expiry + Grace Period

- After `expiresAt`, the name enters a **90-day grace period**.
- During grace: the name is **not active** — transfers are blocked, resolver reads return empty, resolver writes revert.
- During grace: **renewal is allowed** and extends from the original `expiresAt` (not from current time).
- Anyone can call `renew()` for any name (not restricted to the owner).

### 4. Full Expiration

- After `expiresAt + GRACE_PERIOD`, the name is fully expired.
- It can be re-registered by anyone through a new commit-reveal cycle.
- Re-registration increments the `epoch`, invalidating all existing subdomains.
- Re-registration increments `recordVersion`, clearing all resolver data.

### 5. Premium Pricing (Dutch Auction)

Immediately after a name fully expires (grace period ends), a premium is charged on top of the base fee. The premium starts at `maxPremium` (default: 100 ETH) and decays linearly to 0 over `premiumDecayPeriod` (default: 21 days).

```
premium = maxPremium * (premiumDecayPeriod - elapsed) / premiumDecayPeriod
```

Where `elapsed` is seconds since `expiresAt + GRACE_PERIOD`. After the decay period, premium is 0.

---

## Fee Structure

### Defaults at Deployment

The contract deploys with `defaultFee = 0.001 ETH` for all label lengths. No length-specific fees are set at deployment.

### Admin-Configurable Fees

The owner can set per-length fees via `setLengthFees()`. When a length-specific fee is set, it overrides the default. The owner can also change the default fee.

```
getFee(length):
  if lengthFeeSet[length] → return lengthFees[length]
  else → return defaultFee
```

The fee is determined by `bytes(label).length` (UTF-8 byte length, not character count). For example, an emoji label may be 4 bytes despite being 1 "character".

### Renewal Fee

Renewal costs the same as the base registration fee for that label length. No premium is charged on renewal.

---

## Subdomains

### Registration

- Parent owner calls `registerSubdomain(label, parentId)` or `registerSubdomainFor(label, parentId, to)`.
- Subdomains are **free** (no fee).
- Subdomains have **no independent expiry** — they are active as long as the parent chain is active.
- Maximum nesting depth: 10 levels below the top-level name.

### Epoch-Based Invalidation

Each name record has an `epoch` counter. When a subdomain is created, it stores `parentEpoch` — the parent's epoch at creation time. A subdomain is considered **stale** (inactive) if its `parentEpoch` does not match the parent's current `epoch`.

This happens when:
- The parent name expires and is re-registered (epoch increments).
- The parent owner reclaims the subdomain via `registerSubdomain()` (burns the old token, mints a new one with incremented epoch).

Stale subdomains:
- Return empty strings from resolver reads.
- Show `[Invalid]` in `tokenURI`.
- Cannot be transferred (blocked by `_isActive` check in `_beforeTokenTransfer`).

### Reclaim

The parent owner can always call `registerSubdomain()` with an existing subdomain label. This burns the old token (clearing the previous owner's holding), increments the epoch, and mints a fresh token to the parent owner. The previous owner's `primaryName` is cleared if it pointed to the reclaimed token.

**Note:** `isAvailable()` returns `false` for active subdomains, even though the parent owner can overwrite them. Parent owners should call `registerSubdomain()` directly — it will succeed for reclaim regardless of `isAvailable()` result.

---

## Record Versioning

Each token has a `recordVersion` counter. All resolver data (address, contenthash, multi-coin addresses, text records) is keyed by `(tokenId, recordVersion)`. When a name is re-registered after expiry, `recordVersion` is incremented, effectively clearing all previous resolver data without paying gas to delete storage.

---

## Resolution

### Forward Resolution

```
resolve(tokenId):
  if name is not active → return address(0)
  if explicit address is set → return that address
  else → return ownerOf(tokenId)
```

The fallback to `ownerOf` means a freshly registered name resolves to its owner by default.

### Reverse Resolution

Users set a **primary name** via `setPrimaryName(tokenId)`. The caller must be the token owner or the address that the token resolves to.

```
reverseResolve(addr):
  if primaryName[addr] is 0, or name is not active, or resolve(tokenId) != addr → return ""
  else → return "label.wei" (or "sub.label.wei" etc.)
```

Setting `primaryName` to `tokenId = 0` clears the primary name.

### Multi-Coin Addresses

`setAddrForCoin(tokenId, coinType, addr)` stores addresses for any SLIP-44 coin type. For coin type 60 (ETH), the `addr()` function first checks the explicit coin address, then falls back to `resolve()`.

### Text Records

Standard key-value text records via `setText` / `text`. Common keys: `avatar`, `url`, `description`, `com.twitter`, `com.github`, etc.

### Contenthash

`setContenthash` / `contenthash` for IPFS/Swarm/etc. content addressing. Used by the gateway (`wei.domains`) to serve websites.

---

## Normalization & Validation

### On-Chain Validation (`_validateAndNormalize`)

The contract enforces:
- Label byte length: 1–255 bytes
- Valid UTF-8 encoding (rejects invalid sequences, overlong encodings, surrogates, codepoints above U+10FFFF)
- No control characters (0x00–0x1F), space (0x20), dot (0x2E), or DEL (0x7F)
- No leading or trailing hyphens
- ASCII A–Z is lowercased to a–z

The contract does **not** perform Unicode normalization (NFC/NFD), confusable detection, or script restriction. These are delegated to the client layer.

### Off-Chain Normalization (ENSIP-15)

For proper Unicode safety, callers SHOULD pre-normalize labels using [ENSIP-15](https://docs.ens.domains/ensip/15/) via the `@adraffy/ens-normalize` library before calling the contract.

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

### Why Client-Side Normalization

1. **Future-proof** — Normalization standards evolve (ENSIP-15 replaced ENSIP-1, Unicode updates yearly). On-chain rules would be frozen or require expensive upgrades.
2. **Ecosystem alignment** — ENS, DNS, and other naming systems handle normalization at the application layer.
3. **International support** — Overly restrictive on-chain validation could block legitimate international names.
4. **Gas efficiency** — Full Unicode normalization tables are impractical on-chain.

### Helper Functions

- `normalize(label)` — On-chain validation + ASCII lowercasing. Reverts on invalid input.
- `isAsciiLabel(label)` — Returns `true` if label is pure ASCII. If true, on-chain normalization is sufficient.
- `computeNamehash(fullName)` — Computes namehash for a full name (e.g., `"sub.name"` or `"sub.name.wei"`). Lowercases ASCII but does not validate label characters (no UTF-8 check, no hyphen rules). Does reject empty labels (leading/trailing/consecutive dots). Strips `.wei` suffix if present.
- `computeId(fullName)` — Returns `uint256(computeNamehash(fullName))`.

---

## Access Control

| Function | Access |
|---|---|
| `commit` | Anyone |
| `reveal` | Anyone (must match commitment owner) |
| `registerSubdomain` / `registerSubdomainFor` | Parent token owner only |
| `renew` | Anyone (for any name) |
| `setAddr`, `setContenthash`, `setAddrForCoin`, `setText` | Token owner only |
| `setPrimaryName` | Token owner or resolved address |
| `setDefaultFee`, `setLengthFees`, `clearLengthFee`, `setPremiumSettings` | Contract owner only |
| `withdraw` | Contract owner only |

---

## Transfer Restrictions

The `_beforeTokenTransfer` hook blocks transfers of **inactive** tokens. A token is inactive when:
- Top-level name: `block.timestamp > expiresAt` (after expiry, including during grace period)
- Subdomain: parent epoch mismatch, or parent chain is inactive

Mint (`from == address(0)`) and burn (`to == address(0)`) are always allowed regardless of active status.

---

## Security Properties

### Reentrancy Protection

The following functions have the `nonReentrant` modifier:
- `reveal` — uses `_safeMint` which calls `onERC721Received` on contract recipients
- `registerSubdomain` / `registerSubdomainFor` — also uses `_safeMint`
- `renew` — sends ETH refund
- `withdraw` — sends ETH

### Refund Handling

`reveal` and `renew` refund excess ETH to `msg.sender` via `SafeTransferLib.safeTransferETH`. If the caller cannot receive ETH (e.g., a contract without a `receive` function), the transaction reverts.

### Frontrunning Protection

The commit-reveal scheme requires a 60-second minimum delay between commit and reveal, preventing miners/searchers from observing a reveal transaction and frontrunning it.

### Primary Name Cleanup

When a name is re-registered or a subdomain is reclaimed, if the previous owner's `primaryName` pointed to that token, it is deleted.

---

## Contract Interface

### Read Functions

```solidity
// Registration helpers
function makeCommitment(string label, address owner, bytes32 secret) pure returns (bytes32)
function isAvailable(string label, uint256 parentId) view returns (bool)
function getFee(uint256 length) view returns (uint256)
function getPremium(uint256 tokenId) view returns (uint256)
function normalize(string label) pure returns (string)
function isAsciiLabel(string label) pure returns (bool)

// Lookup
function computeId(string fullName) pure returns (uint256)
function computeNamehash(string fullName) pure returns (bytes32)
function getFullName(uint256 tokenId) view returns (string)

// Expiration
function expiresAt(uint256 tokenId) view returns (uint256)
function isExpired(uint256 tokenId) view returns (bool)     // true after expiresAt + GRACE_PERIOD
function inGracePeriod(uint256 tokenId) view returns (bool) // true between expiresAt and expiresAt + GRACE_PERIOD

// Resolution (uint256 tokenId overloads)
function resolve(uint256 tokenId) view returns (address)
function reverseResolve(address addr) view returns (string)
function contenthash(uint256 tokenId) view returns (bytes)
function text(uint256 tokenId, string key) view returns (string)
function addr(uint256 tokenId, uint256 coinType) view returns (bytes)

// Resolution (bytes32 node overloads — ENS-compatible)
function addr(bytes32 node) view returns (address)
function addr(bytes32 node, uint256 coinType) view returns (bytes)
function text(bytes32 node, string key) view returns (string)
function contenthash(bytes32 node) view returns (bytes)

// ERC-165
function supportsInterface(bytes4 interfaceId) view returns (bool)
// Supported: ERC-721, ERC-165, addr(bytes32) [0x3b3b57de], addr(bytes32,uint256) [0xf1cb7e06],
//            text [0x59d1d43c], contenthash [0xbc1c58d1]

// ERC-721 read functions
function name() pure returns (string)             // "Wei Name Service"
function symbol() pure returns (string)           // "WEI"
function tokenURI(uint256 tokenId) view returns (string)
function ownerOf(uint256 tokenId) view returns (address)
function balanceOf(address owner) view returns (uint256)
function getApproved(uint256 tokenId) view returns (address)
function isApprovedForAll(address owner, address operator) view returns (bool)

// Storage accessors (auto-generated)
function records(uint256 tokenId) view returns (string label, uint256 parent, uint64 expiresAt, uint64 epoch, uint64 parentEpoch)
function recordVersion(uint256 tokenId) view returns (uint256)
function commitments(bytes32) view returns (uint256)
function primaryName(address) view returns (uint256)
function defaultFee() view returns (uint256)
function maxPremium() view returns (uint256)
function premiumDecayPeriod() view returns (uint256)
function lengthFees(uint256) view returns (uint256)
function lengthFeeSet(uint256) view returns (bool)
function WEI_NODE() view returns (bytes32)
```

### Write Functions

```solidity
// Commit-reveal registration
function commit(bytes32 commitment)
function reveal(string label, bytes32 secret) payable returns (uint256 tokenId)

// Subdomains
function registerSubdomain(string label, uint256 parentId) returns (uint256 tokenId)
function registerSubdomainFor(string label, uint256 parentId, address to) returns (uint256 tokenId)

// Renewal
function renew(uint256 tokenId) payable

// Resolver writes (token owner only)
function setAddr(uint256 tokenId, address addr)
function setContenthash(uint256 tokenId, bytes hash)
function setAddrForCoin(uint256 tokenId, uint256 coinType, bytes addr)
function setText(uint256 tokenId, string key, string value)

// Reverse resolution
function setPrimaryName(uint256 tokenId)

// Admin (contract owner only)
function setDefaultFee(uint256 fee)
function setLengthFees(uint256[] lengths, uint256[] fees)
function clearLengthFee(uint256 length)
function setPremiumSettings(uint256 maxPremium, uint256 decayPeriod)
function withdraw()

// Standard ERC-721
function transferFrom(address from, address to, uint256 tokenId)
function safeTransferFrom(address from, address to, uint256 tokenId)
function safeTransferFrom(address from, address to, uint256 tokenId, bytes data)
function approve(address to, uint256 tokenId)
function setApprovalForAll(address operator, bool approved)
```

---

## Events

```solidity
// Registration
event NameRegistered(uint256 indexed tokenId, string label, address indexed owner, uint256 expiresAt)
event SubdomainRegistered(uint256 indexed tokenId, uint256 indexed parentId, string label)
event NameRenewed(uint256 indexed tokenId, uint256 newExpiresAt)
event PrimaryNameSet(address indexed addr, uint256 indexed tokenId)
event Committed(bytes32 indexed commitment, address indexed committer)

// ENS-compatible resolver events
event AddrChanged(bytes32 indexed node, address addr)
event ContenthashChanged(bytes32 indexed node, bytes contenthash)
event AddressChanged(bytes32 indexed node, uint256 coinType, bytes addr)
event TextChanged(bytes32 indexed node, string indexed key, string value)

// Admin
event DefaultFeeChanged(uint256 fee)
event LengthFeeChanged(uint256 indexed length, uint256 fee)
event LengthFeeCleared(uint256 indexed length)
event PremiumSettingsChanged(uint256 maxPremium, uint256 decayPeriod)
```

---

## Custom Errors

| Error | Condition |
|---|---|
| `Expired()` | Operation requires active name but name is expired/inactive |
| `TooDeep()` | Subdomain nesting exceeds `MAX_SUBDOMAIN_DEPTH` (10) |
| `EmptyLabel()` | Label is empty or name contains consecutive dots |
| `InvalidName()` | Label contains invalid characters or fails validation |
| `InvalidLength()` | Label byte length outside 1–255 range |
| `LengthMismatch()` | `setLengthFees` called with mismatched array lengths |
| `NotParentOwner()` | Subdomain registration attempted by non-parent-owner |
| `PremiumTooHigh()` | Admin tried to set premium > 10,000 ETH |
| `InsufficientFee()` | `msg.value` less than required fee + premium |
| `AlreadyCommitted()` | Commitment already exists and hasn't expired |
| `CommitmentTooNew()` | Reveal attempted before `MIN_COMMITMENT_AGE` (60s) |
| `CommitmentTooOld()` | Reveal attempted after `MAX_COMMITMENT_AGE` (24h) |
| `AlreadyRegistered()` | Top-level name still active or in grace period |
| `CommitmentNotFound()` | No matching commitment on-chain |
| `DecayPeriodTooLong()` | Admin tried to set decay period > 3,650 days |

The contract also uses inherited errors:
- `Unauthorized()` (from Ownable) — used in `setAddr`, `setContenthash`, `setAddrForCoin`, `setText`, `setPrimaryName`, and `renew` (subdomains cannot be renewed)
- `TokenDoesNotExist()` (from ERC721) — used in `tokenURI` and `renew` when the token has no record

---

## Storage Layout

```solidity
// Fee configuration
uint256 public defaultFee;
uint256 public maxPremium;
uint256 public premiumDecayPeriod;
mapping(uint256 => uint256) public lengthFees;
mapping(uint256 => bool) public lengthFeeSet;

// Name records
mapping(uint256 => NameRecord) public records;   // tokenId → record
mapping(uint256 => uint256) public recordVersion; // tokenId → version (increments on re-registration)

// Commitments
mapping(bytes32 => uint256) public commitments;   // commitment hash → timestamp

// Reverse resolution
mapping(address => uint256) public primaryName;   // address → tokenId

// Versioned resolver data (keyed by tokenId, recordVersion)
mapping(uint256 => mapping(uint256 => address)) internal _resolvedAddress;
mapping(uint256 => mapping(uint256 => bytes)) internal _contenthash;
mapping(uint256 => mapping(uint256 => mapping(uint256 => bytes))) internal _coinAddr;
mapping(uint256 => mapping(uint256 => mapping(string => string))) internal _text;

struct NameRecord {
    string label;        // Normalized label (ASCII lowercased)
    uint256 parent;      // Parent token ID (0 for top-level)
    uint64 expiresAt;    // Expiry timestamp (0 for subdomains)
    uint64 epoch;        // Increments on re-registration
    uint64 parentEpoch;  // Parent's epoch at time of subdomain creation
}
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

## Verification Tool

The official dapp includes a "verify name" helper:
- Enter a token ID (from OpenSea URL, etc.)
- See the actual on-chain name and byte representation
- Check ENSIP-15 normalization status
- Compare against an expected name

Useful for secondary market purchases or inspecting unfamiliar names.

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
5. **Check `isActive` state** before displaying resolver data — expired names return empty from all resolver reads
6. **Handle refund failures** — if your contract calls `reveal` or `renew`, ensure it can receive ETH refunds

---

## Links

- **Dapp:** https://wei.domains
- **Contract:** https://etherscan.io/address/0x0000000000696760E15f265e828DB644A0c242EB
- **OpenSea:** https://opensea.io/collection/wei-name-service
- **ENSIP-15:** https://docs.ens.domains/ensip/15/
- **ens-normalize:** https://github.com/adraffy/ens-normalize.js
