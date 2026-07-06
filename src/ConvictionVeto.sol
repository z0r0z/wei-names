// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Multicallable} from "solady/utils/Multicallable.sol";

/// @dev Minimal subset of WeiDAO this contract reads and calls.
interface IWeiDAO {
    function nft() external view returns (address);
    function alpha() external view returns (uint256);
    function threshold() external view returns (uint256);
    function weightOf(uint256 tokenId) external view returns (uint256);
    function proposalCount() external view returns (uint256);
    function veto(uint256 id) external;
}

/// @dev Minimal subset of NameNFT this contract reads.
interface INameNFT {
    function ownerOf(uint256 id) external view returns (address);
    function records(uint256 id)
        external
        view
        returns (
            string memory label,
            uint256 parent,
            uint64 expiresAt,
            uint64 epoch,
            uint64 parentEpoch
        );
}

/// @title ConvictionVeto
/// @notice A decentralized "no" layer for WeiDAO. Holds the `veto.dao.wei` role and lets WNS name
///         holders build *veto-conviction* against a live proposal using the **exact same** weight
///         source (`WeiDAO.weightOf`) and conviction math (with WeiDAO's live `alpha`) as the support
///         side. Once a proposal's veto-conviction reaches WeiDAO's own `threshold`, anyone may call
///         {veto} and the proposal is cancelled on the DAO. This turns support-only conviction voting
///         into support-*and*-oppose, with symmetric cost (vetoing costs as much sustained weight as
///         passing). Back or withdraw with several names in one transaction via the inherited
///         {Multicallable-multicall}.
///
/// @dev Safety by construction:
///      • The veto role is *negative power only* — the worst this contract can ever do is cancel
///        proposals. It cannot touch the treasury or NameNFT.
///      • It holds the role NFT but has **no** path to move it (or any funds) out, so the role is
///        bound to this contract's logic. Because the DAO owns the parent `dao.wei`, governance can
///        reassign the role away at any time (`registerSubdomainFor`) — so it can never be stranded.
///      • While `exec.dao.wei` is live, exec can reassign this role *instantly* via
///        `dao.rescue(nameNFT, 0, registerSubdomainFor("veto", dao.wei, newHolder))` — an escape hatch
///        that bypasses the proposal flow (and therefore this contract's own veto). Keep exec live
///        until minority-veto governance is proven in production.
///      • The only WeiDAO state it changes is through `dao.veto(id)`, which does not re-enter here.
contract ConvictionVeto is Multicallable {
    error NotHolder();
    error NoProposal();
    error InvalidNFT();
    error NotEligible();
    error NotSupporting();
    error WeightTooLarge();
    error BelowThreshold();
    error AlreadySupported();

    event VetoSupported(
        uint256 indexed id, uint256 indexed tokenId, address indexed supporter, uint256 weight
    );
    event VetoUnsupported(
        uint256 indexed id, uint256 indexed tokenId, address indexed supporter, uint256 weight
    );
    event Vetoed(uint256 indexed id);

    /// @dev Fixed-point scale, matching WeiDAO.
    uint256 internal constant SCALE = 1e18;

    /// @notice tokenId of `veto.dao.wei` — the only NFT this contract accepts via `safeTransferFrom`.
    ///         Equals WeiDAO's `VETO_ROLE` (namehash of "veto.dao.wei").
    uint256 public constant VETO_ROLE =
        0xa3cbec6f0a52ab020919800d82007684e63632feadb0f555ac3cf796ec121dc1;

    IWeiDAO public immutable dao;
    INameNFT public immutable nft;

    /// @dev Per-proposal accrued veto-conviction (mirrors WeiDAO's per-proposal accumulator).
    struct Prop {
        uint64 lastUpdate;
        uint256 conviction;
        uint256 supportWeight;
    }

    mapping(uint256 => Prop) public props;

    /// @dev id => tokenId => support snapshot (weight + name epoch/expiry), same shape/semantics as
    ///      WeiDAO: a stale position (runway elapsed or name re-registered) is permissionlessly prunable
    ///      so expired weight can't wrongly drive a veto. Read weight via {supportOf}.
    struct Support {
        uint128 weight;
        uint64 epoch;
        uint64 expiresAt;
    }

    mapping(uint256 => mapping(uint256 => Support)) private _positions;

    constructor(IWeiDAO dao_) {
        dao = dao_;
        nft = INameNFT(dao_.nft());
    }

    /// @notice Back a *veto* of proposal `id` with a name you own; its weight accrues veto-conviction.
    /// @dev Batch several names in one transaction with {Multicallable-multicall}.
    function support(uint256 id, uint256 tokenId) external {
        _support(id, tokenId);
    }

    /// @notice Withdraw a name's veto-support. The current owner may withdraw anytime; anyone may
    ///         prune a stale position (support-time runway elapsed, or the name was re-registered).
    function unsupport(uint256 id, uint256 tokenId) external {
        Support memory s = _positions[id][tokenId];
        uint256 w = s.weight;
        if (w == 0) revert NotSupporting();
        (,,, uint64 epoch,) = nft.records(tokenId);
        bool stale = block.timestamp >= s.expiresAt || epoch != s.epoch;
        if (!stale && nft.ownerOf(tokenId) != msg.sender) revert NotHolder();

        Prop storage p = props[id];
        _sync(p);
        p.supportWeight -= w;
        delete _positions[id][tokenId];

        emit VetoUnsupported(id, tokenId, msg.sender, w);
    }

    /// @notice Veto-conviction against proposal `id`, accrued to now.
    function convictionOf(uint256 id) public view returns (uint256) {
        Prop storage p = props[id];
        if (p.lastUpdate == 0) return 0;
        return _accrue(p.conviction, p.supportWeight, block.timestamp - p.lastUpdate);
    }

    /// @notice Weight from name `tokenId` currently backing a veto of proposal `id` (0 = none).
    function supportOf(uint256 id, uint256 tokenId) external view returns (uint256) {
        return _positions[id][tokenId].weight;
    }

    /// @notice Whether proposal `id` now has enough veto-conviction to be cancelled via {veto}.
    /// @dev Mirrors WeiDAO's `passed`: checks conviction ≥ threshold only. {veto} additionally needs
    ///      this contract to hold `veto.dao.wei` at call time.
    function vetoable(uint256 id) public view returns (bool) {
        return convictionOf(id) >= dao.threshold();
    }

    /// @notice Once veto-conviction reaches WeiDAO's `threshold`, cancel the proposal (permissionless).
    /// @dev Requires this contract to currently hold `veto.dao.wei`, else `dao.veto` reverts. If the
    ///      proposal is already executed `dao.veto` reverts; if already vetoed it is idempotent.
    function veto(uint256 id) external {
        if (!vetoable(id)) revert BelowThreshold();
        dao.veto(id);
        emit Vetoed(id);
    }

    /// @dev Accept *only* the `veto.dao.wei` role NFT via `safeTransferFrom`; reject any other token so
    ///      stray NFTs can't be trapped in this contract (which has no transfer-out path).
    function onERC721Received(address, address, uint256 tokenId, bytes calldata)
        external
        view
        returns (bytes4)
    {
        if (msg.sender != address(nft) || tokenId != VETO_ROLE) revert InvalidNFT();
        return this.onERC721Received.selector;
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Shared support path. Deliberately does not read WeiDAO's proposal struct: its calldata
    ///      `bytes` is unbounded, so touching it on every call would make the veto path asymmetrically
    ///      pricier than the support side. A closed proposal can still be "supported" — that's just
    ///      wasted gas; `dao.veto` stays the final gate.
    function _support(uint256 id, uint256 tokenId) internal {
        if (id == 0 || id > dao.proposalCount()) revert NoProposal();
        if (_positions[id][tokenId].weight != 0) revert AlreadySupported();
        if (nft.ownerOf(tokenId) != msg.sender) revert NotHolder();

        uint256 w = dao.weightOf(tokenId); // identical weight to the support side
        if (w == 0) revert NotEligible();
        if (w > type(uint128).max) revert WeightTooLarge();

        Prop storage p = props[id];
        _sync(p);
        p.supportWeight += w;
        (,, uint64 exp, uint64 epoch,) = nft.records(tokenId);
        _positions[id][tokenId] = Support(uint128(w), epoch, exp);

        emit VetoSupported(id, tokenId, msg.sender, w);
    }

    // Conviction math — identical recurrence to WeiDAO, reading WeiDAO's live `alpha`.

    function _sync(Prop storage p) internal {
        if (p.lastUpdate == 0) {
            p.lastUpdate = uint64(block.timestamp);
            return;
        }
        uint256 dt = block.timestamp - p.lastUpdate;
        if (dt != 0) {
            p.conviction = _accrue(p.conviction, p.supportWeight, dt);
            p.lastUpdate = uint64(block.timestamp);
        }
    }

    /// @dev conviction' = c·α^dt + w·(1 − α^dt)/(1 − α), using WeiDAO's live `alpha`.
    function _accrue(uint256 c, uint256 w, uint256 dt) internal view returns (uint256) {
        if (dt == 0) return c;
        uint256 alpha = dao.alpha();
        uint256 a = _pow(alpha, dt);
        return (c * a / SCALE) + (w * (SCALE - a) / (SCALE - alpha));
    }

    function _pow(uint256 base, uint256 exp) internal pure returns (uint256 result) {
        result = SCALE;
        while (exp != 0) {
            if (exp & 1 == 1) result = result * base / SCALE;
            base = base * base / SCALE;
            exp >>= 1;
        }
    }
}
