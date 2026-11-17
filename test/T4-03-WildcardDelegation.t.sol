// SPDX-License-Identifier: MIT
// T4-03 — Wildcard delegation check (mechanics confirmation, NOT a finding).
// Question: does a delegate.xyz delegation with rights == bytes32(0) (documented
// "encompass all rights") granted to the DIAMOND satisfy the diamond's per-rule
// check isRightsDelegated(delegatee, delegator, DELEGATION_RULES_SESSION)?
// If yes, one wildcard grant defeats the diamond's per-rule separation — but the
// precondition is the victim themself delegating wildcard rights TO THE ATTACKER,
// which is intended delegate.xyz semantics and a compromised-user precondition,
// not a flaw in the diamond. This test only records the observed mechanics.
//
// PoC (Base mainnet fork, block 58427268).
// Run:  BASE_RPC_URL=https://mainnet.base.org forge test --match-contract T403WildcardDelegation -vvv
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IDelegateRegistry {
    function delegateContract(address to, address contract_, bytes32 rights, bool enable) external payable returns (bytes32);
    function delegateAll(address to, bytes32 rights, bool enable) external payable returns (bytes32);
}

interface IDiamondDelegation {
    function isRightsDelegated(address delegatee_, address delegator_, bytes32 rights_) external view returns (bool);
    function getRegistry() external view returns (address);
}

contract T403WildcardDelegation is Test {
    address constant DIAMOND = 0x6aBE1d282f72B474E54527D93b979A4f64d3030a;
    uint256 constant FORK_BLOCK = 58427268;

    function testWildcardDelegationMechanics() public {
        vm.createSelectFork(vm.envOr("BASE_RPC_URL", string("https://mainnet.base.org")), FORK_BLOCK);
        address victim = makeAddr("victim");
        address attacker = makeAddr("attacker");
        bytes32 sessionRules = keccak256("delegation.rules.session");
        IDiamondDelegation diamond = IDiamondDelegation(DIAMOND);
        IDelegateRegistry registry = IDelegateRegistry(diamond.getRegistry());

        assertEq(address(registry), 0x00000000000000447e69651d841bD8D104Bed493, "live registry is delegate.xyz");
        assertFalse(diamond.isRightsDelegated(attacker, victim, sessionRules), "no delegation initially");

        // Victim grants the attacker a WILDCARD (rights == 0) delegation for the diamond.
        vm.prank(victim);
        registry.delegateContract(attacker, DIAMOND, bytes32(0), true);
        bool wildcardGrantsSession = diamond.isRightsDelegated(attacker, victim, sessionRules);
        emit log_named_string("wildcard contract delegation grants SESSION rights", wildcardGrantsSession ? "YES" : "NO");

        // Victim revokes; attacker gets a full-wallet wildcard instead.
        vm.prank(victim);
        registry.delegateContract(attacker, DIAMOND, bytes32(0), false);
        assertFalse(diamond.isRightsDelegated(attacker, victim, sessionRules), "revoked");
        vm.prank(victim);
        registry.delegateAll(attacker, bytes32(0), true);
        bool allGrantsSession = diamond.isRightsDelegated(attacker, victim, sessionRules);
        emit log_named_string("delegateAll wildcard grants SESSION rights", allGrantsSession ? "YES" : "NO");

        // Mechanics recorded; verdict is REJECTED regardless: both paths require
        // the victim to delegate wildcard rights to the attacker themself.
        assertTrue(wildcardGrantsSession || allGrantsSession, "at least one wildcard path grants rights");
    }
}
