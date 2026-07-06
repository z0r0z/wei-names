// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "@forge/Test.sol";
import {ConvictionVeto, IWeiDAO} from "../src/ConvictionVeto.sol";

interface ICreateX {
    function deployCreate3(bytes32 salt, bytes calldata initCode) external payable returns (address);
}

/// @notice Mainnet-fork rehearsal of the exact ConvictionVeto deploy: as the deployer EOA, call
///         `CreateX.deployCreate3(salt, initCode)` and assert it lands on the mined vanity address and
///         wires to the live DAO/NFT. Self-skips unless `RUN_FORK_SIM=true`.
///         Run: `RUN_FORK_SIM=true forge test --match-contract ConvictionVetoDeploySim -vv`.
contract ConvictionVetoDeploySim is Test {
    address constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
    address constant DEPLOYER = 0x1C0Aa8cCD568d90d61659F060D1bFb1e6f855A20; // owns the sender-bound salt
    address constant DAO = 0x00000007988A79d16cf76B5dc4cF54dc3Af24936; // live WeiDAO
    address constant NFT = 0x0000000000696760E15f265e828DB644A0c242EB; // live NameNFT

    bytes32 constant SALT = 0x1c0aa8ccd568d90d61659f060d1bfb1e6f855a20009941d8f734fa232b5bdfd0;
    address constant PREDICTED = 0x0000005260725EEe99704957218d4045A50C2051;

    function testForkDeploy() public {
        if (!vm.envOr("RUN_FORK_SIM", false)) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork("https://ethereum-rpc.publicnode.com");

        // The exact bytes the wallet submits as initCode; assert they equal the saved deploy artifact.
        bytes memory initCode = abi.encodePacked(type(ConvictionVeto).creationCode, abi.encode(DAO));
        assertEq(
            keccak256(initCode),
            0xc6068562db0e779eadddc8dd532e708f7e63871644cf7e8893bd838a92cd0e70,
            "initCode != ops/cv_initcode.hex"
        );

        vm.prank(DEPLOYER);
        address cv = ICreateX(CREATEX).deployCreate3(SALT, initCode);

        assertEq(cv, PREDICTED, "deployed address != predicted");
        assertEq(address(ConvictionVeto(cv).dao()), DAO, "dao immutable");
        assertEq(address(ConvictionVeto(cv).nft()), NFT, "nft pulled from dao.nft()");
        assertEq(
            ConvictionVeto(cv).VETO_ROLE(),
            0xa3cbec6f0a52ab020919800d82007684e63632feadb0f555ac3cf796ec121dc1
        );
        emit log_named_address("ConvictionVeto deployed at", cv);
    }
}
