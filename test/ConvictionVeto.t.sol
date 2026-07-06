// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "@forge/Test.sol";
import {NameNFT} from "../src/NameNFT.sol";
import {WeiDAO} from "../src/WeiDAO.sol";
import {ConvictionVeto, IWeiDAO} from "../src/ConvictionVeto.sol";

/// @notice Proves the peripheral ConvictionVeto contract can hold the veto role, accrue a "no" vote
///         with the DAO's own weight + conviction math, and cancel a proposal once it crosses the bar
///         — while the executor keeps its own instant veto and the DAO can reclaim the role anytime.
contract ConvictionVetoTest is Test {
    NameNFT nft;
    WeiDAO dao;
    ConvictionVeto cv;

    address holder = makeAddr("holder"); // holds dao.wei before handing it to the DAO
    address execMs = makeAddr("execMs"); // exec role
    address proposer = makeAddr("proposer");
    address whale = makeAddr("whale");
    address stranger = makeAddr("stranger");

    uint256 constant ALPHA_7D = 999_998_853_923_940_000;
    uint256 threshold;
    uint256 tDao;
    uint256 tWhale;

    function setUp() public {
        // Calibrate so one "aa"-name-year of sustained weight crosses the bar in ~one half-life.
        threshold = 0.05 ether * 1e18 / (1e18 - ALPHA_7D) / 2;
        nft = new NameNFT();
        dao = new WeiDAO(address(nft), ALPHA_7D, threshold, 0, 0, address(0));
        cv = new ConvictionVeto(IWeiDAO(address(dao)));

        uint256[] memory lens = new uint256[](1);
        uint256[] memory fees = new uint256[](1);
        (lens[0], fees[0]) = (2, 0.05 ether);
        vm.prank(nft.owner());
        nft.setLengthFees(lens, fees);

        // Register dao.wei, mint the roles (exec -> multisig, veto -> ConvictionVeto), then gift
        // dao.wei to the DAO so the roles resolve under a DAO-held parent.
        tDao = _register("dao", holder);
        assertEq(tDao, dao.PROPOSAL_PARENT());
        vm.startPrank(holder);
        nft.registerSubdomainFor("exec", tDao, execMs);
        nft.registerSubdomainFor("veto", tDao, address(cv));
        nft.transferFrom(holder, address(dao), tDao);
        vm.stopPrank();

        tWhale = _register("aa", whale); // 2-char name -> full-tier weight
        uint256 bb = _register("bb", proposer); // proposer needs a weighted primary name
        vm.prank(proposer);
        nft.setPrimaryName(bb);
    }

    function testRolesResolve() public view {
        assertEq(dao.vetoer(), address(cv)); // the contract is the vetoer
        assertEq(dao.executor(), execMs); // multisig keeps exec
    }

    function testVetoFiresWhenConvictionCrossesThreshold() public {
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "to be vetoed");

        vm.prank(whale);
        cv.support(id, tWhale);
        assertEq(cv.supportOf(id, tWhale), dao.weightOf(tWhale)); // same weight as the support side

        assertFalse(cv.vetoable(id)); // not enough veto-conviction yet
        vm.expectRevert(ConvictionVeto.BelowThreshold.selector);
        cv.veto(id);

        vm.warp(block.timestamp + 8 days); // sustain the "no" past one half-life
        assertGe(cv.convictionOf(id), dao.threshold());
        assertTrue(cv.vetoable(id));

        vm.prank(stranger); // triggering is permissionless
        cv.veto(id);

        (,,, bool vetoed,,,,,) = dao.proposals(id);
        assertTrue(vetoed); // cancelled on the DAO
    }

    function testExecutorCanStillCancelDirectly() public {
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");
        // exec cancels instantly, independent of the ConvictionVeto contract
        vm.prank(execMs);
        dao.veto(id);
        (,,, bool vetoed,,,,,) = dao.proposals(id);
        assertTrue(vetoed);
    }

    function testDaoCanReclaimTheRole() public {
        address newHolder = makeAddr("newVeto");
        vm.prank(address(dao)); // the DAO owns dao.wei -> overwrites the subdomain
        nft.registerSubdomainFor("veto", tDao, newHolder);
        assertEq(dao.vetoer(), newHolder); // role moved off the contract

        // the contract can no longer cancel — it's no longer the vetoer
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");
        vm.prank(whale);
        cv.support(id, tWhale);
        vm.warp(block.timestamp + 8 days);
        vm.expectRevert(WeiDAO.Unauthorized.selector);
        cv.veto(id);
    }

    function testUnsupportWithdrawsAndDecays() public {
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");
        vm.prank(whale);
        cv.support(id, tWhale);

        // Capture the base once and warp to absolute offsets: under via_ir the optimizer treats the
        // TIMESTAMP opcode as tx-invariant (true in prod, false under repeated vm.warp), so re-reading
        // block.timestamp between warps can reuse a stale value and no-op the second warp.
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 4 days);
        uint256 built = cv.convictionOf(id);
        assertGt(built, 0);

        vm.prank(whale); // owner withdraws its "no"
        cv.unsupport(id, tWhale);
        assertEq(cv.supportOf(id, tWhale), 0);

        vm.warp(t0 + 8 days);
        assertLt(cv.convictionOf(id), built); // conviction decays with no weight behind it

        vm.warp(t0 + 68 days); // can never reach threshold now
        vm.expectRevert(ConvictionVeto.BelowThreshold.selector);
        cv.veto(id);
    }

    function testSupportRejectsNonOwnerAndSubdomains() public {
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");

        vm.prank(stranger); // doesn't own the whale's name
        vm.expectRevert(ConvictionVeto.NotHolder.selector);
        cv.support(id, tWhale);

        uint256 sub = _registerSub("x", tWhale, whale); // x.aa.wei -> 0 weight
        vm.prank(whale);
        vm.expectRevert(ConvictionVeto.NotEligible.selector);
        cv.support(id, sub);
    }

    function testRejectsInvalidProposalId() public {
        vm.startPrank(whale);
        vm.expectRevert(ConvictionVeto.NoProposal.selector);
        cv.support(0, tWhale); // id 0
        vm.expectRevert(ConvictionVeto.NoProposal.selector);
        cv.support(1, tWhale); // > proposalCount (none exist yet)
        vm.stopPrank();
    }

    function testSupportOnClosedProposalIsHarmless() public {
        // support() deliberately doesn't read WeiDAO's (unbounded) proposal struct, so a closed
        // proposal isn't blocked from being veto-supported — it's just wasted gas; dao.veto is the
        // final gate. This keeps the veto path from being asymmetrically pricier than the support side.
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");
        vm.prank(execMs);
        dao.veto(id); // exec closes it first
        vm.prank(whale);
        cv.support(id, tWhale); // no revert
        assertGt(cv.supportOf(id, tWhale), 0);
    }

    function testRejectsDoubleSupport() public {
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");
        vm.startPrank(whale);
        cv.support(id, tWhale);
        vm.expectRevert(ConvictionVeto.AlreadySupported.selector);
        cv.support(id, tWhale); // same name twice
        vm.stopPrank();
    }

    function testUnsupportRequiresPosition() public {
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");
        vm.prank(whale);
        vm.expectRevert(ConvictionVeto.NotSupporting.selector);
        cv.unsupport(id, tWhale); // nothing to withdraw
    }

    function testMultipleNamesStackVetoWeight() public {
        uint256 tWhale2 = _register("ab", whale); // a second full-tier name for the whale
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");

        uint256 w1 = dao.weightOf(tWhale);
        uint256 w2 = dao.weightOf(tWhale2);
        vm.startPrank(whale);
        cv.support(id, tWhale);
        cv.support(id, tWhale2);
        vm.stopPrank();

        (,, uint256 supportWeight) = cv.props(id);
        assertEq(supportWeight, w1 + w2); // both names stack onto the same veto
    }

    function testStalePositionIsPrunablePermissionlessly() public {
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");
        vm.prank(whale);
        cv.support(id, tWhale);

        // Once the name's registered runway elapses, its weight is stale and anyone may prune it —
        // so expired weight can't keep driving a veto and there's no owner-gated cleanup deadlock.
        vm.warp(block.timestamp + 366 days);
        vm.prank(stranger); // not the owner
        cv.unsupport(id, tWhale);
        assertEq(cv.supportOf(id, tWhale), 0);
    }

    function testVetoRoleConstantMatchesDao() public view {
        assertEq(cv.VETO_ROLE(), dao.VETO_ROLE()); // hardcoded namehash matches the live DAO's
    }

    function testReceiverAcceptsOnlyVetoRole() public {
        uint256 role = cv.VETO_ROLE(); // hoist before pranking (arg eval would consume the prank)

        // Accepts the veto role from the NameNFT (the real assignment path safe-mints it).
        vm.prank(address(nft));
        assertEq(
            cv.onERC721Received(address(0), address(0), role, ""),
            bytes4(0x150b7a02) // IERC721Receiver.onERC721Received.selector
        );
        // Rejects any other tokenId from the NameNFT (e.g. exec.dao.wei or a stray name).
        vm.prank(address(nft));
        vm.expectRevert(ConvictionVeto.InvalidNFT.selector);
        cv.onERC721Received(address(0), address(0), 12345, "");
        // Rejects the veto tokenId from a non-NameNFT sender.
        vm.prank(stranger);
        vm.expectRevert(ConvictionVeto.InvalidNFT.selector);
        cv.onERC721Received(address(0), address(0), role, "");
    }

    function testMinorityVetoBeatsLargerSupport() public {
        // Design intent, locked in: the veto needs only 1× threshold and *no* execution delay, so a
        // smaller opposition cancels a proposal even when the support side already has far more
        // conviction and would otherwise pass. Here support = two full-tier names (convictionMax = 4×
        // threshold); opposition = one full-tier name (convictionMax = 2× threshold).
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");

        // Support side (yes): two names -> overwhelming conviction.
        uint256 yes2 = _register("cd", whale);
        vm.startPrank(whale);
        dao.support(id, tWhale);
        dao.support(id, yes2);
        vm.stopPrank();

        // Opposition (no): a single name, half the support weight.
        address opp = makeAddr("opp");
        uint256 no1 = _register("ef", opp);
        vm.prank(opp);
        cv.support(id, no1);

        // Sustain both well past a half-life.
        vm.warp(block.timestamp + 14 days);
        assertGe(dao.convictionOf(id), 2 * dao.threshold()); // support would pass comfortably
        assertTrue(cv.vetoable(id)); // opposition, at half the weight, still crosses the bar

        vm.prank(stranger); // anyone triggers it
        cv.veto(id);

        // The proposal is dead even though it was support-eligible: execute checks `vetoed` first.
        vm.expectRevert(WeiDAO.Vetoed.selector);
        dao.execute(id);
    }

    function testMulticallBatchesSupport() public {
        uint256 tWhale2 = _register("ab", whale); // a second full-tier name for the whale
        vm.prank(proposer);
        uint256 id = dao.propose(address(nft), 0, "", "x");

        uint256 expected = dao.weightOf(tWhale) + dao.weightOf(tWhale2);
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(ConvictionVeto.support, (id, tWhale));
        calls[1] = abi.encodeCall(ConvictionVeto.support, (id, tWhale2));

        vm.prank(whale);
        cv.multicall(calls); // both names back the veto in one transaction

        (,, uint256 supportWeight) = cv.props(id);
        assertEq(supportWeight, expected); // both stacked
        assertGt(cv.supportOf(id, tWhale), 0);
        assertGt(cv.supportOf(id, tWhale2), 0);
    }

    function _register(string memory label, address to) internal returns (uint256 id) {
        bytes32 secret = keccak256(bytes(label));
        vm.startPrank(to);
        nft.commit(nft.makeCommitment(label, to, secret));
        vm.warp(block.timestamp + 61);
        uint256 fee = nft.getFee(bytes(label).length);
        vm.deal(to, fee);
        id = nft.reveal{value: fee}(label, secret);
        vm.stopPrank();
    }

    function _registerSub(string memory label, uint256 parent, address to)
        internal
        returns (uint256)
    {
        vm.prank(to);
        return nft.registerSubdomainFor(label, parent, to);
    }
}
