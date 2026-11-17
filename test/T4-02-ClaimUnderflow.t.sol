// SPDX-License-Identifier: MIT
// T4-02 — LumerinDiamond claimForProvider() arithmetic underflow (transient).
// claimForProvider computes
//     amount = _getProviderRewards(session, bid, true) - _getProviderOnHoldAmount(session, bid)
// with NO dispute check and NO underflow guard. After an undisputed early close
// the provider has ALREADY been paid in full at close time, so
// _getProviderRewards == 0, while _getProviderOnHoldAmount is still > 0 for the
// rest of the close day. The subtraction underflows and claimForProvider reverts
// (Panic 0x11) until startOfDay(closedAt) + 1 day, when the on-hold amount drops
// to 0 and the call succeeds again (paying 0). No funds are lost — the provider
// was already paid in full — so this is a transient DoS on a no-op claim, not a
// submittable loss. Recorded here with a PoC to prove the revert is real.
//
// PoC (Base mainnet fork, block 58427268, diamond 0x6aBE...3030a).
// Run:  BASE_RPC_URL=https://mainnet.base.org forge test --match-contract T402ClaimUnderflow -vvv
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface ILumerinDiamond {
    struct Session {
        address user;
        bytes32 bidId;
        uint256 stake;
        bytes closeoutReceipt;
        uint256 closeoutType;
        uint256 providerWithdrawnAmount;
        uint128 openedAt;
        uint128 endsAt;
        uint128 closedAt;
        bool isActive;
        bool isDirectPaymentFromUser;
    }

    function providerRegister(address provider_, uint256 amount_, string calldata endpoint_) external;
    function modelRegister(
        address modelOwner_,
        bytes32 baseModelId_,
        bytes32 ipfsCID_,
        uint256 fee_,
        uint256 amount_,
        string calldata name_,
        string[] memory tags_
    ) external;
    function postModelBid(address provider_, bytes32 modelId_, uint256 pricePerSecond_) external returns (bytes32);
    function getModelId(address account_, bytes32 baseModelId_) external pure returns (bytes32);
    function getBidId(address provider_, bytes32 modelId_, uint256 nonce_) external pure returns (bytes32);
    function openSession(
        address user_,
        uint256 amount_,
        bool isDirectPaymentFromUser_,
        bytes calldata approvalEncoded_,
        bytes calldata signature_
    ) external returns (bytes32);
    function getSession(bytes32 sessionId_) external view returns (Session memory);
    function closeSession(bytes calldata receiptEncoded_, bytes calldata signature_) external;
    function claimForProvider(bytes32 sessionId_) external;
    function getFundingAccount() external view returns (address);
}

contract T402ClaimUnderflow is Test {
    address constant DIAMOND = 0x6aBE1d282f72B474E54527D93b979A4f64d3030a;
    address constant MOR = 0x7431aDa8a591C955a994a21710752EF9b882b8e3;
    uint256 constant FORK_BLOCK = 58427268;
    uint256 constant CHAIN_ID = 8453;
    uint256 constant PPS = 46296296296296;

    uint256 providerPk = 0xA11CE;
    address provider;
    address user;

    ILumerinDiamond diamond;
    IERC20 mor;
    bytes32 bidId;

    function setUp() public {
        vm.createSelectFork(vm.envOr("BASE_RPC_URL", string("https://mainnet.base.org")), FORK_BLOCK);
        provider = vm.addr(providerPk);
        user = makeAddr("user");
        diamond = ILumerinDiamond(DIAMOND);
        mor = IERC20(MOR);

        deal(MOR, provider, 500 ether);
        deal(MOR, user, 20000 ether);
        vm.prank(provider);
        mor.approve(DIAMOND, type(uint256).max);
        vm.prank(user);
        mor.approve(DIAMOND, type(uint256).max);

        vm.prank(provider);
        diamond.providerRegister(provider, 100 ether, "https://provider.example:8082");
        bytes32 baseModelId = bytes32(uint256(1));
        vm.prank(provider);
        diamond.modelRegister(provider, baseModelId, bytes32("ipfs://test"), 0, 100 ether, "test", new string[](0));
        bytes32 modelId = diamond.getModelId(provider, baseModelId);
        vm.prank(provider);
        diamond.postModelBid(provider, modelId, PPS);
        bidId = diamond.getBidId(provider, modelId, 0);
    }

    function _ethSign(uint256 pk, bytes memory payload) internal pure returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(payload)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function testClaimRevertsAfterUndisputedEarlyClose() public {
        // User opens a session (valid approval for the user) and closes it
        // EARLY (1 day in, 7-day session) with a VALID provider receipt.
        bytes memory approval = abi.encode(bidId, CHAIN_ID, user, uint128(block.timestamp));
        bytes memory approvalSig = _ethSign(providerPk, approval);
        vm.prank(user);
        bytes32 sessionId = diamond.openSession(user, 20000 ether, false, approval, approvalSig);

        ILumerinDiamond.Session memory s = diamond.getSession(sessionId);
        uint256 providerBefore = mor.balanceOf(provider);

        vm.warp(s.openedAt + 1 days);
        bytes memory receipt = abi.encode(sessionId, CHAIN_ID, uint128(block.timestamp), uint32(5000), uint32(100));
        bytes memory receiptSig = _ethSign(providerPk, receipt);
        vm.prank(user);
        diamond.closeSession(receipt, receiptSig);

        // Provider was paid in full at close (1 day * pps == 4 MOR).
        uint256 paidAtClose = mor.balanceOf(provider) - providerBefore;
        assertEq(paidAtClose, 1 days * PPS, "provider paid in full at close");
        assertEq(diamond.getSession(sessionId).providerWithdrawnAmount, paidAtClose, "withdrawn recorded");

        // Same-day claimForProvider underflows: rewards(0) - onHold(>0).
        vm.expectRevert(abi.encodeWithSignature("Panic(uint256)", 0x11));
        vm.prank(provider);
        diamond.claimForProvider(sessionId);

        // Next day the on-hold amount is 0 and the call succeeds (paying 0).
        vm.warp(block.timestamp + 1 days);
        vm.prank(provider);
        diamond.claimForProvider(sessionId);
        assertEq(mor.balanceOf(provider) - providerBefore, paidAtClose, "no additional payment, no loss");
        emit log_named_uint("provider MOR paid at close", paidAtClose);
    }
}
