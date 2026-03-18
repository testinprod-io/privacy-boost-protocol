// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2026 Sunnyside Labs Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {Withdrawal, ForcedWithdrawalRequest, AuthSnapshotState, TreeRootPair} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {console} from "forge-std/console.sol";

import {MockERC20, MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

contract ForcedWithdrawal2StepTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD); // Separate proxy admin to avoid TransparentProxy routing issue
    address alice = makeAddr("alice");
    address relay = makeAddr("relay");
    address operator = makeAddr("operator");

    uint16 tokenId;
    uint96 constant AMOUNT = 1000 ether;
    uint256 constant AUTH_SNAPSHOT_INTERVAL = 300;

    function setUp() public {
        verifier = new MockVerifier();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);

        // Fund the pool (simulating private deposits)
        token.mint(address(pool), 100_000 ether);

        // Set operator
        pool.setOperator(operator);

        // Setup relay
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        // Establish an initial snapshot for the current round so permissionless forced withdrawals
        // can validate against an existing snapshot (requestForcedWithdrawal must not create snapshots).
        uint256[] memory treeNums = new uint256[](1);
        treeNums[0] = 0;
        vm.prank(relay);
        pool.snapshotAuthTrees(treeNums);
    }

    function _toArrays(uint256 nullifier, uint256 commitment)
        internal
        pure
        returns (uint256[] memory nullifiers, uint256[] memory commitments)
    {
        nullifiers = new uint256[](1);
        nullifiers[0] = nullifier;
        commitments = new uint256[](1);
        commitments[0] = commitment;
    }

    function _getRequestKey(address requester, uint256[] memory commitments) internal pure returns (uint256) {
        bytes32 commitmentsHash = keccak256(abi.encodePacked(commitments));
        return uint256(keccak256(abi.encodePacked(requester, commitmentsHash)));
    }

    function _makeWithdrawal(address to, uint16 tid, uint96 amt) internal pure returns (Withdrawal memory) {
        return Withdrawal({to: to, tokenId: tid, amount: amt});
    }

    function _getAuthRoots() internal view returns (TreeRootPair[] memory) {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: authRegistry.authTreeRoot(0)});
        return roots;
    }

    function _snapshotTree0ForCurrentRound() internal {
        uint256[] memory treeNums = new uint256[](1);
        treeNums[0] = 0;
        vm.prank(relay);
        pool.snapshotAuthTrees(treeNums);
    }

    // ========== Step 1: Request ==========

    function test_requestForcedWithdrawal() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Check request stored (key = keccak256(requester, commitmentsHash))
        uint256 requestKey = _getRequestKey(alice, commitments);
        (
            uint64 requestBlock,
            address requester,
            address withdrawalTo,
            uint16 tid,
            uint96 amt,
            uint16 storedFeeBps,
            uint8 inputCount,
            uint256 spenderAccountId,
            bytes32 nullifiersHash,
            bytes32 commitmentsHash
        ) = pool.forcedWithdrawalRequests(requestKey);

        assertEq(requestBlock, block.number);
        assertEq(requester, alice);
        assertEq(withdrawalTo, alice);
        assertEq(tid, tokenId);
        assertEq(amt, AMOUNT);
        assertEq(storedFeeBps, pool.withdrawFeeBps()); // Fee rate stored at request time
        assertEq(inputCount, 1);
        assertEq(spenderAccountId, 12345);
        assertEq(nullifiersHash, keccak256(abi.encodePacked(nullifiers)));
        assertEq(commitmentsHash, keccak256(abi.encodePacked(commitments)));

        // Check commitment to requestKey mapping
        assertEq(pool.commitmentToRequestKey(commitments[0]), requestKey);
    }

    function test_requestForcedWithdrawal_emitsEvent() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());

        TreeRootPair[] memory authRoots = _getAuthRoots();
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit IPrivacyBoost.ForcedWithdrawalRequested(alice, alice, tokenId, AMOUNT, nullifiers, commitments);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_nullifierAlreadySpent() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // First request to simulate a spent nullifier scenario
        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Wait and execute to spend the nullifier
        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        vm.prank(alice);
        pool.executeForcedWithdrawal(nullifiers, commitments);

        // Now try to request again with the same (now spent) nullifier - need new commitment
        (uint256[] memory nullifiers2, uint256[] memory commitments2) = _toArrays(123, 789);
        authRoots = _getAuthRoots();
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidNullifierSet.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers2,
            commitments2,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_alreadyRequested() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Try to request again (same commitment already has pending request)
        authRoots = _getAuthRoots();
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.ForcedWithdrawalAlreadyRequested.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_zeroAddress() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(address(0), tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidWithdrawal.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_unregisteredTokenId() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, uint16(999), AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidWithdrawal.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Ensure the commitment wasn't locked.
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
    }

    function test_revertWhen_duplicateTreeNumberInKnownRoots() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(321, 654);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // Duplicate tree number in knownRoots should be rejected.
        TreeRootPair[] memory knownRoots = new TreeRootPair[](2);
        knownRoots[0] = TreeRootPair({treeNumber: 0, root: rootVal});
        knownRoots[1] = TreeRootPair({treeNumber: 0, root: rootVal});

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.DuplicateTreeNumber.selector);
        pool.requestForcedWithdrawal(
            knownRoots,
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    // ========== Step 2: Execute ==========

    function test_executeForcedWithdrawal() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // Step 1: Request (with proof verification)
        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Wait for delay
        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        uint256 aliceBalBefore = token.balanceOf(alice);

        // Step 2: Execute (no proof needed, nullifiers + commitments for hash verification)
        vm.prank(alice);
        pool.executeForcedWithdrawal(nullifiers, commitments);

        // Check token transferred
        assertEq(token.balanceOf(alice), aliceBalBefore + AMOUNT);

        // Check request cleared
        uint256 requestKey = _getRequestKey(alice, commitments);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertEq(requestBlock, 0);

        // Check commitment mapping cleared
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);

        // Check nullifier spent
        assertTrue(pool.nullifierSpent(nullifiers[0]));
    }

    function test_revertWhen_executeTooEarly() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Don't wait for delay
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.ForcedWithdrawalTooEarly.selector);
        pool.executeForcedWithdrawal(nullifiers, commitments);
    }

    function test_revertWhen_notRequested() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.ForcedWithdrawalNotRequested.selector);
        pool.executeForcedWithdrawal(nullifiers, commitments);
    }

    function test_executeForcedWithdrawal_permissionlessCaller() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        address bob = makeAddr("bob");
        uint256 aliceBalBefore = token.balanceOf(alice);
        vm.prank(bob);
        pool.executeForcedWithdrawal(nullifiers, commitments);

        // Check token transferred to withdrawal recipient (Alice)
        assertEq(token.balanceOf(alice), aliceBalBefore + AMOUNT);

        // Check request cleared
        uint256 requestKey = _getRequestKey(alice, commitments);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertEq(requestBlock, 0);

        // Check commitment mapping cleared
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);

        // Check nullifier spent
        assertTrue(pool.nullifierSpent(nullifiers[0]));
    }

    // ========== Cancel ==========

    function test_cancelForcedWithdrawal() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        vm.prank(alice);
        pool.cancelForcedWithdrawal(nullifiers, commitments);

        // Check request cleared
        uint256 requestKey = _getRequestKey(alice, commitments);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertEq(requestBlock, 0);

        // Check commitment mapping cleared
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
    }

    function test_revertWhen_cancelNotRequester() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        // Bob tries to cancel Alice's request - Bob is neither the requester nor the account owner
        address bob = makeAddr("bob");
        vm.prank(bob);
        vm.expectRevert(IPrivacyBoost.NotRequesterOrOwner.selector);
        pool.cancelForcedWithdrawal(nullifiers, commitments);
    }

    function test_revertWhen_cancelTooEarly() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Don't wait
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.ForcedWithdrawalTooEarly.selector);
        pool.cancelForcedWithdrawal(nullifiers, commitments);
    }

    // ========== Transfer Priority (Core DoS Prevention) ==========

    function test_transferWins_whenExecutedBeforeForcedWithdrawal() public {
        // Use two different nullifiers: one for forced withdrawal, one to simulate transfer winning
        (uint256[] memory nullifiers1, uint256[] memory commitments1) = _toArrays(111, 222);
        (uint256[] memory nullifiers2, uint256[] memory commitments2) = _toArrays(333, 444);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        Withdrawal memory withdrawal1 = _makeWithdrawal(alice, tokenId, AMOUNT);
        Withdrawal memory withdrawal2 = _makeWithdrawal(alice, tokenId, AMOUNT);

        // Alice requests forced withdrawal for commitment 222
        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers1,
            commitments1,
            withdrawal1,
            EpochHelpers.dummyProof()
        );

        // Alice also requests forced withdrawal for commitment 444
        authRoots = _getAuthRoots();
        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers2,
            commitments2,
            withdrawal2,
            EpochHelpers.dummyProof()
        );

        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        // Execute second request first (simulating normal transfer that wins)
        vm.prank(alice);
        pool.executeForcedWithdrawal(nullifiers2, commitments2);

        // Nullifier 333 is now spent
        assertTrue(pool.nullifierSpent(nullifiers2[0]));

        // Alice can still execute her forced withdrawal for commitment 222
        vm.prank(alice);
        pool.executeForcedWithdrawal(nullifiers1, commitments1);

        // Both nullifiers are now spent
        assertTrue(pool.nullifierSpent(nullifiers1[0]));
        assertTrue(pool.nullifierSpent(nullifiers2[0]));
    }

    // ========== Prover DoS Prevention Test ==========

    function test_proverDoS_preventsAttackerWithFakeNullifier() public {
        // This test demonstrates that with proof verification at request time,
        // an attacker cannot create fake requests for existing commitments.
        // The MockVerifier always returns true, but in production, the attacker
        // would need a valid proof which requires knowing the note's secret.

        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // Alice (the legitimate owner) can request because she can generate valid proof
        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Verify request is stored
        uint256 requestKey = _getRequestKey(alice, commitments);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertTrue(requestBlock != 0);

        // Verify commitment mapping is set
        assertEq(pool.commitmentToRequestKey(commitments[0]), requestKey);

        // In production:
        // - Attacker would try to create fake request with random nullifier
        // - But the circuit verifies nullifier = Poseidon(noteSecret, leafIndex)
        // - Without noteSecret, attacker cannot generate valid proof
        // - So only the legitimate owner can request forced withdrawal
    }

    // ========== New Design: Request Key Per Batch ==========

    function test_multiInput_singleRequestKey() public {
        // Test that multiple input notes create a single request with hash-based verification
        uint256[] memory nullifiers = new uint256[](2);
        nullifiers[0] = 100;
        nullifiers[1] = 200;
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Check single request exists
        uint256 requestKey = _getRequestKey(alice, commitments);
        (uint64 requestBlock,, address withdrawalTo,,,, uint8 inputCount,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertTrue(requestBlock != 0);
        assertEq(withdrawalTo, alice);
        assertEq(inputCount, 2);

        // Check both commitments map to same requestKey
        assertEq(pool.commitmentToRequestKey(commitments[0]), requestKey);
        assertEq(pool.commitmentToRequestKey(commitments[1]), requestKey);

        // Wait and execute
        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        vm.prank(alice);
        pool.executeForcedWithdrawal(nullifiers, commitments);

        // Check all cleared
        (requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertEq(requestBlock, 0);
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
        assertEq(pool.commitmentToRequestKey(commitments[1]), 0);
        assertTrue(pool.nullifierSpent(nullifiers[0]));
        assertTrue(pool.nullifierSpent(nullifiers[1]));
    }

    function test_revertWhen_hashMismatch() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        // Try to execute with wrong nullifiers (hash won't match)
        uint256[] memory wrongNullifiers = new uint256[](1);
        wrongNullifiers[0] = 999;

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.ForcedWithdrawalMismatch.selector);
        pool.executeForcedWithdrawal(wrongNullifiers, commitments);
    }

    function test_revertWhen_inputCountMismatch() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(123, 456);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        // Try to execute with different number of inputs
        uint256[] memory twoNullifiers = new uint256[](2);
        twoNullifiers[0] = 123;
        twoNullifiers[1] = 456;
        uint256[] memory twoCommitments = new uint256[](2);
        twoCommitments[0] = 456;
        twoCommitments[1] = 789;

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.ForcedWithdrawalMismatch.selector);
        pool.executeForcedWithdrawal(twoNullifiers, twoCommitments);
    }

    // ========== Auth Snapshot Validation Tests ==========

    /// @notice Test that request with current round snapshot succeeds
    function test_requestWithCurrentRoundSnapshot() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(777, 888);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        uint256 currentRound = block.number / AUTH_SNAPSHOT_INTERVAL;

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, currentRound),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Verify request was stored
        uint256 requestKey = _getRequestKey(alice, commitments);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertGt(requestBlock, 0, "Request should be stored with current round snapshot");
    }

    /// @notice Forced withdrawals must not be able to create new snapshots (prevents first-caller race)
    function test_revertWhen_currentRoundNotSnapshotted() public {
        // Move to a new round without taking a snapshot for it
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 5); // Round 5

        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(1234, 5678);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());

        uint256 currentRound = block.number / AUTH_SNAPSHOT_INTERVAL;
        assertEq(currentRound, 5);

        TreeRootPair[] memory authRoots = _getAuthRoots();

        // No relay snapshot has been taken for round 5, so this must revert.
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.AuthTreeNotSnapshotted.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, currentRound),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Once the relay snapshots, the same round becomes usable.
        _snapshotTree0ForCurrentRound();

        authRoots = _getAuthRoots();
        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, currentRound),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    /// @notice Test that request with previous round snapshot succeeds (grace period)
    function test_requestWithPreviousRoundSnapshot() public {
        // Warp to a known block so we have predictable rounds
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 10); // Start at round 10

        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(111, 222);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        uint256 snapshotRound = block.number / AUTH_SNAPSHOT_INTERVAL; // Should be 10

        // Create snapshot for current round (round 10) via relay-controlled snapshot function
        _snapshotTree0ForCurrentRound();
        assertEq(pool.latestSnapshotRound(), snapshotRound, "latestSnapshotRound should update on snapshot");
        assertEq(pool.authSnapshots(snapshotRound, 0), authRegistry.authTreeRoot(0), "snapshot root mismatch");

        // Roll forward to next round (round 11)
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 11);

        // Request with previous round snapshot (round 10, grace period allows N-1)
        TreeRootPair[] memory authRoots = _getAuthRoots();
        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, snapshotRound),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Verify request was stored
        uint256 requestKey = _getRequestKey(alice, commitments);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertGt(requestBlock, 0, "Request should be stored with previous round snapshot");
    }

    /// @notice Test that request with too old snapshot (N-2) reverts
    function test_revertWhen_authSnapshotTooOld() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(333, 444);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());

        // Get current round, then try to use a round that's N-2
        uint256 currentRound = block.number / AUTH_SNAPSHOT_INTERVAL;
        uint256 tooOldRound = 0; // Round 0 when we're at any round >= 2

        // Make sure we're at least at round 2 so round 0 is "too old"
        if (currentRound < 2) {
            vm.roll(AUTH_SNAPSHOT_INTERVAL * 2 + 1);
        }

        TreeRootPair[] memory authRoots = _getAuthRoots();
        // Request with round 0 (which is N-2 or older) should fail
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidAuthSnapshotRound.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, tooOldRound),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    /// @notice Test that request with future round reverts
    function test_revertWhen_authSnapshotFutureRound() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(555, 666);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        uint256 currentRound = block.number / AUTH_SNAPSHOT_INTERVAL;
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // Try to use a future round
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidAuthSnapshotRound.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, currentRound + 1),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    // ========== Latest Snapshot Round Tests ==========

    /// @notice Test that latestSnapshotRound is updated when a snapshot is taken
    function test_latestSnapshotRoundUpdated() public {
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 5); // Start at round 5

        // Initially latestSnapshotRound should be 0 (no non-zero snapshots taken)
        assertEq(pool.latestSnapshotRound(), 0, "Initial latestSnapshotRound should be 0");

        _snapshotTree0ForCurrentRound();

        // latestSnapshotRound should now be 5
        assertEq(pool.latestSnapshotRound(), 5, "latestSnapshotRound should be updated to 5");
    }

    /// @notice Test downtime scenario: old proof remains valid until new snapshot is taken
    function test_downtimeScenario_oldProofStillValid() public {
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 10); // Start at round 10

        // Create snapshot at round 10
        _snapshotTree0ForCurrentRound();

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());

        assertEq(pool.latestSnapshotRound(), 10, "latestSnapshotRound should be 10");

        // Simulate long downtime: jump to round 100 (no activity in between)
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 100);

        // latestSnapshotRound is still 10 (no new snapshots taken)
        assertEq(pool.latestSnapshotRound(), 10, "latestSnapshotRound should still be 10 after downtime");

        // User with round 10 proof can still submit (latestSnapshotRound == 10)
        (uint256[] memory nullifiers2, uint256[] memory commitments2) = _toArrays(2003, 2004);
        Withdrawal memory withdrawal2 = _makeWithdrawal(alice, tokenId, AMOUNT);

        TreeRootPair[] memory authRoots = _getAuthRoots();
        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, 10),
            12345,
            nullifiers2,
            commitments2,
            withdrawal2,
            EpochHelpers.dummyProof()
        );

        // Request should be stored
        uint256 requestKey = _getRequestKey(alice, commitments2);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertGt(requestBlock, 0, "Request with old round 10 proof should succeed after downtime");
    }

    /// @notice Test that old proof becomes invalid after new snapshot is taken
    function test_oldProofInvalidAfterNewSubmission() public {
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 10); // Start at round 10

        // Create snapshot at round 10
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        _snapshotTree0ForCurrentRound();

        assertEq(pool.latestSnapshotRound(), 10);

        // Jump to round 100
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 100);

        // Create new snapshot at round 100
        _snapshotTree0ForCurrentRound();

        assertEq(pool.latestSnapshotRound(), 100, "latestSnapshotRound should now be 100");

        // Now user B with old round 10 proof should fail
        // (10 != latestSnapshotRound(100) AND 10+1 != latestSnapshotRound(100))
        (uint256[] memory nullifiers3, uint256[] memory commitments3) = _toArrays(3005, 3006);
        Withdrawal memory withdrawal3 = _makeWithdrawal(alice, tokenId, AMOUNT);

        TreeRootPair[] memory authRoots = _getAuthRoots();
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidAuthSnapshotRound.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, 10),
            12345,
            nullifiers3,
            commitments3,
            withdrawal3,
            EpochHelpers.dummyProof()
        );
    }

    /// @notice Test grace period: latestSnapshotRound - 1 is also valid
    function test_gracePeriodWithLatestSnapshot() public {
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 10); // Start at round 10

        // Create snapshot at round 10
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        _snapshotTree0ForCurrentRound();

        assertEq(pool.latestSnapshotRound(), 10);

        // Roll to round 11 and create snapshot
        vm.roll(AUTH_SNAPSHOT_INTERVAL * 11);

        _snapshotTree0ForCurrentRound();

        assertEq(pool.latestSnapshotRound(), 11);

        // Now round 10 should still work (grace period: latestSnapshotRound - 1)
        (uint256[] memory nullifiers3, uint256[] memory commitments3) = _toArrays(4005, 4006);
        Withdrawal memory withdrawal3 = _makeWithdrawal(alice, tokenId, AMOUNT);

        TreeRootPair[] memory authRoots = _getAuthRoots();
        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, 10),
            12345,
            nullifiers3,
            commitments3,
            withdrawal3,
            EpochHelpers.dummyProof()
        );

        // Should succeed
        uint256 requestKey = _getRequestKey(alice, commitments3);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertGt(requestBlock, 0, "Request with previous round (grace period) should succeed");

        // But round 9 should fail (not in grace period)
        (uint256[] memory nullifiers4, uint256[] memory commitments4) = _toArrays(4007, 4008);
        Withdrawal memory withdrawal4 = _makeWithdrawal(alice, tokenId, AMOUNT);

        authRoots = _getAuthRoots();
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidAuthSnapshotRound.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, 9),
            12345,
            nullifiers4,
            commitments4,
            withdrawal4,
            EpochHelpers.dummyProof()
        );
    }

    // ========== Duplicate Check in Request (Lines 483-488) ==========

    /// @notice Test that duplicate nullifier within same request array reverts
    function test_revertWhen_duplicateNullifierInSameRequestArray() public {
        // Same nullifier appears twice in the array
        uint256[] memory nullifiers = new uint256[](2);
        nullifiers[0] = 999;
        nullifiers[1] = 999; // Duplicate!
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 1001;
        commitments[1] = 1002;

        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.DuplicateNullifier.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    /// @notice Test that duplicate input commitment within same request array reverts
    function test_revertWhen_duplicateInputCommitmentInSameRequestArray() public {
        // Same commitment appears twice in the array
        uint256[] memory nullifiers = new uint256[](2);
        nullifiers[0] = 888;
        nullifiers[1] = 889;
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 2001;
        commitments[1] = 2001; // Duplicate!

        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, AMOUNT);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.DuplicateInputCommitment.selector);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );
    }

    // ========== Coverage Tests: Nullifier Spent via vm.store (Line 631) ==========

    /// @notice Test InvalidNullifierSet in executeForcedWithdrawal when nullifier spent via vm.store (Line 631)
    function test_revertWhen_executeForcedWithdrawal_nullifierSpentViaStore() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(100, 200);
        Withdrawal memory withdrawal = _makeWithdrawal(alice, tokenId, 500 ether);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        // Wait for delay
        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        // Simulate the nullifier being spent through a normal transfer
        // Using vm.store to set nullifierSpent[100] = true
        // nullifierSpent is at storage slot 11 (after operator was added)
        bytes32 nullifierSlot = keccak256(abi.encode(uint256(100), uint256(11)));
        vm.store(address(pool), nullifierSlot, bytes32(uint256(1)));

        // Verify nullifier is now marked as spent
        assertTrue(pool.nullifierSpent(100));

        // Try to execute - should revert with InvalidNullifierSet (Line 631)
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidNullifierSet.selector);
        pool.executeForcedWithdrawal(nullifiers, commitments);
    }
}

/// @notice Tests for forced withdrawal with fees (Line 658)
contract ForcedWithdrawalWithFeeTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address alice = makeAddr("alice");
    address relay = makeAddr("relay");
    address treasury = makeAddr("treasury");
    address operator = makeAddr("operator");

    uint16 tokenId;
    uint96 constant AMOUNT = 1000 ether;
    uint256 constant AUTH_SNAPSHOT_INTERVAL = 300;

    function setUp() public {
        verifier = new MockVerifier();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.withdrawFeeBps = 200;
        cfg.treasury = treasury;
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);

        token.mint(address(pool), 100_000 ether);

        // Set operator
        pool.setOperator(operator);

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        // Establish an initial snapshot for the current round so permissionless forced withdrawals
        // can validate against an existing snapshot (requestForcedWithdrawal must not create snapshots).
        uint256[] memory treeNums = new uint256[](1);
        treeNums[0] = 0;
        vm.prank(relay);
        pool.snapshotAuthTrees(treeNums);
    }

    function _toArrays(uint256 nullifier, uint256 commitment)
        internal
        pure
        returns (uint256[] memory nullifiers, uint256[] memory commitments)
    {
        nullifiers = new uint256[](1);
        nullifiers[0] = nullifier;
        commitments = new uint256[](1);
        commitments[0] = commitment;
    }

    function _getAuthRoots2() internal view returns (TreeRootPair[] memory) {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: authRegistry.authTreeRoot(0)});
        return roots;
    }

    function _makeWithdrawal2(address to, uint16 tid, uint96 amt) internal pure returns (Withdrawal memory) {
        return Withdrawal({to: to, tokenId: tid, amount: amt});
    }

    /// @notice Test withdrawal with fee to treasury in executeForcedWithdrawal (Line 658)
    function test_executeForcedWithdrawal_withFeeToTreasury() public {
        assertEq(pool.withdrawFeeBps(), 200);
        assertEq(pool.treasury(), treasury);

        (uint256[] memory nullifiers, uint256[] memory commitments) = _toArrays(777, 888);
        uint96 grossAmount = AMOUNT;
        Withdrawal memory withdrawal = _makeWithdrawal2(alice, tokenId, grossAmount);

        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots2();

        vm.prank(alice);
        pool.requestForcedWithdrawal(
            EpochHelpers.buildUsedRoots(0, rootVal),
            EpochHelpers.buildAuthState(authRoots, block.number / AUTH_SNAPSHOT_INTERVAL),
            12345,
            nullifiers,
            commitments,
            withdrawal,
            EpochHelpers.dummyProof()
        );

        vm.roll(block.number + pool.forcedWithdrawalDelay() + 1);

        uint256 aliceBalBefore = token.balanceOf(alice);
        uint256 treasuryBalBefore = token.balanceOf(treasury);

        vm.prank(alice);
        pool.executeForcedWithdrawal(nullifiers, commitments);

        // Calculate expected amounts
        uint96 feeAmount = uint96((uint256(grossAmount) * 200) / 10_000); // 2% of 1000 = 20 ether
        uint96 netAmount = grossAmount - feeAmount;

        // Verify alice received net amount
        assertEq(token.balanceOf(alice), aliceBalBefore + netAmount);

        // Verify treasury received fee (Line 658)
        assertEq(token.balanceOf(treasury), treasuryBalBefore + feeAmount);
    }
}
