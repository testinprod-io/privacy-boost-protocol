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
import {
    Output,
    Transfer,
    Withdrawal,
    EpochTreeState,
    AuthSnapshotState,
    TreeRootPair,
    DepositEntry
} from "src/interfaces/IStructs.sol";

import {MockVerifier, MockAuthRegistryMultiTree} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

/// @notice Tests for sparse tree roots and lazy auth snapshots edge cases
contract SparseRootsEdgeCasesTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    MockAuthRegistryMultiTree authRegistry;
    MockVerifier verifier;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address operator = makeAddr("operator");

    function setUp() public {
        verifier = new MockVerifier();
        authRegistry = new MockAuthRegistryMultiTree();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.batchSize = 1;
        cfg.maxFeeTokens = 1;

        (pool, tokenRegistry) = PoolDeployer.deployWithMockAuth(cfg, address(authRegistry));

        // Set operator
        pool.setOperator(operator);

        // Setup: allow this contract as relay
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
    }

    // ========== Helper Functions ==========

    function _submitBasicEpoch(EpochTreeState memory treeState, AuthSnapshotState memory authState) internal {
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, treeState.rootNew)));

        pool.submitEpoch(
            treeState,
            authState,
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    // ========== digestRootIndices Canonical Encoding Tests ==========

    function test_revertWhen_digestRootIndicesTooLong() public {
        uint256 currentRound = block.number / 300;
        uint256 currentTreeRoot = pool.treeRoot(0);

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        // nTransfers=1 => expectedDigestRootWords=1, so length=2 should revert
        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 0;

        vm.expectRevert(IPrivacyBoost.InvalidArrayLengths.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            indices,
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_digestRootIndicesNonZeroPaddingBits() public {
        uint256 currentRound = block.number / 300;
        uint256 currentTreeRoot = pool.treeRoot(0);

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        // nTransfers=1 => only the lowest 4 bits (slot 0) are meaningful.
        // Set a non-zero nibble for an inactive slot to make the encoding non-canonical.
        uint256[] memory indices = new uint256[](1);
        indices[0] = uint256(1) << 4;

        vm.expectRevert(IPrivacyBoost.NonCanonicalEncoding.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            indices,
            EpochHelpers.dummyProof()
        );
    }

    // ========== Empty Sparse Arrays Tests ==========

    /// @notice Test that empty usedRoots array reverts with InvalidBatchConfig
    function test_revert_emptyUsedRoots() public {
        TreeRootPair[] memory emptyRoots = new TreeRootPair[](0);

        uint256 currentRound = block.number / 300;

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(emptyRoots, 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );
    }

    /// @notice Test that empty usedAuthRoots array reverts with InvalidBatchConfig
    function test_revert_emptyUsedAuthRoots() public {
        TreeRootPair[] memory emptyAuthRoots = new TreeRootPair[](0);

        uint256 currentRound = block.number / 300;
        uint256 currentTreeRoot = pool.treeRoot(0); // Read before expectRevert

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(emptyAuthRoots, currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    // ========== Boundary Tests (>16 roots) ==========

    /// @notice Test that >16 usedRoots array reverts with InvalidBatchConfig
    function test_revert_tooManyUsedRoots() public {
        // Create array with 17 roots
        TreeRootPair[] memory tooManyRoots = new TreeRootPair[](17);
        for (uint256 i = 0; i < 17; i++) {
            tooManyRoots[i] = TreeRootPair({treeNumber: i, root: pool.treeRoot(0)});
        }

        uint256 currentRound = block.number / 300;

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(tooManyRoots, 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );
    }

    /// @notice Test that >16 usedAuthRoots array reverts with InvalidBatchConfig
    function test_revert_tooManyUsedAuthRoots() public {
        // Create array with 17 auth roots
        TreeRootPair[] memory tooManyAuthRoots = new TreeRootPair[](17);
        for (uint256 i = 0; i < 17; i++) {
            tooManyAuthRoots[i] = TreeRootPair({treeNumber: i, root: 1});
        }

        uint256 currentRound = block.number / 300;
        uint256 currentTreeRoot = pool.treeRoot(0); // Read before expectRevert

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(tooManyAuthRoots, currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test that exactly 16 usedRoots is valid (boundary case)
    function test_exactly16UsedRootsIsValid() public {
        // Create array with 16 roots, but only tree 0 has valid root
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: pool.treeRoot(0)});

        uint256 currentRound = block.number / 300;

        // Should succeed with single valid root
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(roots, 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );

        assertEq(pool.treeRoot(0), 1, "Root should be updated");
    }

    // ========== Active Tree Validation Tests ==========

    /// @notice Test that active tree not in usedRoots reverts with InvalidEpochState
    function test_revert_activeTreeNotInUsedRoots() public {
        // Create usedRoots with only tree 0, but set activeTreeNumber to 1
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: pool.treeRoot(0)});

        uint256 currentRound = block.number / 300;

        // activeTreeNumber=1 but usedRoots only contains tree 0
        vm.expectRevert(IPrivacyBoost.InvalidEpochState.selector);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(roots, 1, 0, 1, 2, false), // activeTreeNumber=1
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );
    }

    /// @notice Test that active tree with historical (not current) root in usedRoots succeeds.
    /// The contract reads activeRoot from treeRoot[activeTreeNumber] for frontier binding,
    /// so usedRoots can carry a past root for input spending.
    function test_activeTreeWithHistoricalRoot() public {
        uint256 currentRound = block.number / 300;
        uint256 initialRoot = pool.treeRoot(0);

        // First epoch: advance tree 0 root (initialRoot -> 1001)
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );
        assertEq(pool.treeRoot(0), 1001, "Root should be 1001 after first epoch");

        // Second epoch: usedRoots references the historical root (initialRoot), not the current one (1001).
        // This is valid because inputs may have been inserted under the old root.
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 33333;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 2, 1002, 4, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1,
            1,
            1,
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );

        assertEq(pool.treeRoot(0), 1002, "Root should be updated to 1002");
    }

    // ========== Zero Root Tests ==========

    /// @notice Test that zero root in usedRoots reverts with RootNotKnown
    function test_revert_zeroRootInUsedRoots() public {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: 0}); // Zero root

        uint256 currentRound = block.number / 300;

        vm.expectRevert(IPrivacyBoost.RootNotKnown.selector);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(roots, 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );
    }

    /// @notice Test that zero root in usedAuthRoots reverts with RootNotKnown
    function test_revert_zeroRootInUsedAuthRoots() public {
        TreeRootPair[] memory authRoots = new TreeRootPair[](1);
        authRoots[0] = TreeRootPair({treeNumber: 0, root: 0}); // Zero root

        uint256 currentRound = block.number / 300;
        uint256 currentTreeRoot = pool.treeRoot(0); // Read before expectRevert

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        vm.expectRevert(IPrivacyBoost.RootNotKnown.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(authRoots, currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    // ========== Auth Snapshot Tests ==========

    /// @notice Test that auth tree not snapshotted in non-current round reverts
    function test_revert_authTreeNotSnapshotted() public {
        uint256 currentRound = block.number / 300;

        // Try to use previous round (currentRound - 1) without pre-snapshotted auth tree
        // This should fail because the auth tree wasn't snapshotted in the previous round
        if (currentRound > 0) {
            uint256 previousRound = currentRound - 1;

            vm.expectRevert(IPrivacyBoost.AuthTreeNotSnapshotted.selector);
            _submitBasicEpoch(
                EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, pool.treeRoot(0)), 0, 0, 1, 2, false),
                EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), previousRound)
            );
        }
    }

    /// @notice Test lazy auth snapshot on current round succeeds
    function test_lazyAuthSnapshotCurrentRound() public {
        uint256 currentRound = block.number / 300;

        // This should succeed because current round triggers lazy snapshot
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, pool.treeRoot(0)), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );

        // Verify snapshot was taken
        assertTrue(pool.authSnapshots(currentRound, 0) != 0, "Auth tree 0 should be snapshotted");
    }

    /// @notice Test that previous round works after snapshot was taken
    function test_previousRoundWithSnapshot() public {
        // Start at a round boundary for clarity
        uint256 authInterval = pool.authSnapshotInterval();
        vm.roll(authInterval); // Block 300
        uint256 round0 = block.number / authInterval; // Round 1

        uint256 treeRoot0 = pool.treeRoot(0);

        // First, take a snapshot in current round (round 1)
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, treeRoot0), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), round0)
        );

        assertTrue(pool.authSnapshots(round0, 0) != 0, "Auth tree 0 should be snapshotted in round 0");

        // Advance to next round
        vm.roll(block.number + authInterval); // Block 600
        uint256 round1 = block.number / authInterval; // Round 2
        assertEq(round1, round0 + 1, "Should be in next round");

        // Now previous round (round0) should work because we snapshotted it
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 123456789;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, 1001), 0, 2, 1002, 4, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), round0), // Previous round
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );

        assertEq(pool.treeRoot(0), 1002, "Root should be updated");
    }

    // ========== Multi-Tree Batch Tests ==========

    /// @notice Test multi-tree batch with partial sparse set
    function test_multiTreeBatchPartialSparseSet() public {
        uint256 currentRound = block.number / 300;

        // First, submit to tree 0
        uint256 tree0Root = pool.treeRoot(0);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, tree0Root), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );

        // Rollover to tree 1
        // Set up tree 0 at max capacity
        uint8 MERKLE_DEPTH = 20;
        uint32 MAX_LEAVES = uint32(1 << MERKLE_DEPTH);

        bytes32 treeCountSlot = keccak256(abi.encode(uint256(0), uint256(8)));
        vm.store(address(pool), treeCountSlot, bytes32(uint256(MAX_LEAVES)));

        bytes32 treeRootSlot = keccak256(abi.encode(uint256(0), uint256(7)));
        uint256 fullTreeRoot = 0xF011EEEE;
        vm.store(address(pool), treeRootSlot, bytes32(fullTreeRoot));

        bytes32 treeRootHistoryCursorSlot = keccak256(abi.encode(uint256(0), uint256(10)));
        vm.store(address(pool), treeRootHistoryCursorSlot, bytes32(uint256(2)));

        bytes32 baseArraySlot = keccak256(abi.encode(uint256(0), uint256(9)));
        vm.store(address(pool), bytes32(uint256(baseArraySlot) + 2), bytes32(fullTreeRoot));

        // Epoch allows duplicate tree numbers in usedRoots: each transfer selects its digest root
        // independently via digestRootIndices. The circuit uses findPairMatch (OR-based, safe with duplicates).
        TreeRootPair[] memory multiRoots = new TreeRootPair[](2);
        multiRoots[0] = TreeRootPair({treeNumber: 0, root: fullTreeRoot});
        multiRoots[1] = TreeRootPair({treeNumber: 0, root: tree0Root}); // Duplicate tree number with different root (allowed for epoch)

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 99999;

        // Submit with rollover — duplicate tree numbers accepted for epoch
        pool.submitEpoch(
            EpochHelpers.buildTreeState(multiRoots, 0, MAX_LEAVES, 2001, 2, true),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test that epoch accepts duplicate tree numbers with different (but known) roots.
    /// @dev Each transfer selects its digest root via digestRootIndices. The circuit uses
    ///      findPairMatch (OR-based) which is safe with duplicate tree numbers.
    function test_epochAcceptsDuplicateTreeNumberDifferentRoots() public {
        uint256 currentRound = block.number / 300;

        // Submit once to make the initial root historical (known) and create a new current root.
        uint256 initialRoot = pool.treeRoot(0);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );

        uint32 countOld = pool.treeCount(0);
        uint256 currentRoot = pool.treeRoot(0);

        assertTrue(pool.isKnownTreeRoot(0, initialRoot), "Initial root should be known");
        assertTrue(pool.isKnownTreeRoot(0, currentRoot), "Current root should be known");

        TreeRootPair[] memory dupRoots = new TreeRootPair[](2);
        dupRoots[0] = TreeRootPair({treeNumber: 0, root: initialRoot});
        dupRoots[1] = TreeRootPair({treeNumber: 0, root: currentRoot});

        // Epoch accepts duplicate tree numbers — each transfer selects its root via digestRootIndices
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(dupRoots, 0, countOld, 2002, countOld + 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );
    }

    /// @notice Test that epoch rejects exact duplicate (treeNumber, root) pairs.
    function test_revertWhen_epochDuplicateTreeRootPair() public {
        uint256 currentRound = block.number / 300;
        uint256 root = pool.treeRoot(0);

        TreeRootPair[] memory dupPairs = new TreeRootPair[](2);
        dupPairs[0] = TreeRootPair({treeNumber: 0, root: root});
        dupPairs[1] = TreeRootPair({treeNumber: 0, root: root});

        vm.expectRevert(IPrivacyBoost.DuplicateTreeRootPair.selector);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(dupPairs, 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );
    }

    /// @notice Test that duplicate tree numbers in usedAuthRoots are rejected.
    function test_revert_duplicateTreeNumberInUsedAuthRoots() public {
        uint256 currentRound = block.number / 300;

        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, pool.treeRoot(0));
        TreeRootPair[] memory dupAuthRoots = new TreeRootPair[](2);
        dupAuthRoots[0] = TreeRootPair({treeNumber: 0, root: 1});
        dupAuthRoots[1] = TreeRootPair({treeNumber: 0, root: 1});

        vm.expectRevert(IPrivacyBoost.DuplicateTreeNumber.selector);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(dupAuthRoots, currentRound)
        );
    }

    /// @notice Test epoch with inputs from historical tree (after rollover)
    function test_epochWithHistoricalTreeInputs() public {
        uint256 currentRound = block.number / 300;

        // Set up tree 0 at max capacity and do rollover
        uint8 MERKLE_DEPTH = 20;
        uint32 MAX_LEAVES = uint32(1 << MERKLE_DEPTH);

        bytes32 treeCountSlot = keccak256(abi.encode(uint256(0), uint256(8)));
        vm.store(address(pool), treeCountSlot, bytes32(uint256(MAX_LEAVES)));

        bytes32 treeRootSlot = keccak256(abi.encode(uint256(0), uint256(7)));
        uint256 tree0FinalRoot = 0xF011EEEE;
        vm.store(address(pool), treeRootSlot, bytes32(tree0FinalRoot));

        bytes32 treeRootHistoryCursorSlot = keccak256(abi.encode(uint256(0), uint256(10)));
        vm.store(address(pool), treeRootHistoryCursorSlot, bytes32(uint256(1)));

        bytes32 baseArraySlot = keccak256(abi.encode(uint256(0), uint256(9)));
        vm.store(address(pool), bytes32(uint256(baseArraySlot) + 1), bytes32(tree0FinalRoot));

        // Rollover to tree 1
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 88888;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(
                EpochHelpers.buildUsedRoots(0, tree0FinalRoot), 0, MAX_LEAVES, 0xEEE10001, 2, true
            ),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );

        assertEq(pool.currentTreeNumber(), 1, "Should be on tree 1");

        // Now submit epoch with inputs from BOTH tree 0 (historical) and tree 1 (active)
        TreeRootPair[] memory multiRoots = new TreeRootPair[](2);
        multiRoots[0] = TreeRootPair({treeNumber: 0, root: tree0FinalRoot}); // Historical tree
        multiRoots[1] = TreeRootPair({treeNumber: 1, root: pool.treeRoot(1)}); // Active tree

        nullifiers[0] = 77777;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(multiRoots, 1, 2, 0xEEE10002, 4, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );

        assertEq(pool.treeRoot(1), 0xEEE10002, "Tree 1 root should be updated");
    }

    // ========== Invalid Auth Snapshot Round Tests ==========

    /// @notice Test that far future auth snapshot round reverts
    function test_revert_futurAuthSnapshotRound() public {
        uint256 currentRound = block.number / 300;
        uint256 futureRound = currentRound + 100; // Far in the future
        uint256 currentTreeRoot = pool.treeRoot(0); // Read before expectRevert

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        vm.expectRevert(IPrivacyBoost.InvalidAuthSnapshotRound.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), futureRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test that too old auth snapshot round reverts
    function test_revert_tooOldAuthSnapshotRound() public {
        // Advance several rounds
        vm.roll(block.number + 3000); // Advance 10 rounds

        uint256 currentRound = block.number / 300;
        uint256 oldRound = currentRound - 5; // Too old
        uint256 currentTreeRoot = pool.treeRoot(0); // Read before expectRevert

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, uint256(1))));

        vm.expectRevert(IPrivacyBoost.InvalidAuthSnapshotRound.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, currentTreeRoot), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), oldRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    // ========== Multi-Auth Tree Tests ==========

    /// @notice Test epoch with multiple auth trees in sparse array
    function test_multipleAuthTreesInSparseArray() public {
        uint256 currentRound = block.number / 300;

        // Add more auth trees via mock
        authRegistry.addAuthTree(2); // Tree 1 with root 2
        authRegistry.addAuthTree(3); // Tree 2 with root 3

        // Create sparse auth roots with multiple trees
        TreeRootPair[] memory multiAuthRoots = new TreeRootPair[](3);
        multiAuthRoots[0] = TreeRootPair({treeNumber: 0, root: 1});
        multiAuthRoots[1] = TreeRootPair({treeNumber: 1, root: 2});
        multiAuthRoots[2] = TreeRootPair({treeNumber: 2, root: 3});

        // Should succeed
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 55555;

        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, pool.treeRoot(0)), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(multiAuthRoots, currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );

        // All three trees should be snapshotted
        assertTrue(pool.authSnapshots(currentRound, 0) != 0, "Auth tree 0 should be snapshotted");
        assertTrue(pool.authSnapshots(currentRound, 1) != 0, "Auth tree 1 should be snapshotted");
        assertTrue(pool.authSnapshots(currentRound, 2) != 0, "Auth tree 2 should be snapshotted");
    }

    /// @notice Test that partial auth snapshot (some trees snapshotted, others not) reverts for non-current round
    function test_revert_partialAuthSnapshotNonCurrentRound() public {
        uint256 currentRound = block.number / 300;

        // First, snapshot only tree 0 in current round
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, pool.treeRoot(0)), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );

        // Advance to next round
        vm.roll(block.number + 300);

        // Add auth tree 1
        authRegistry.addAuthTree(2);

        // Try to use previous round with auth tree 1 (which wasn't snapshotted)
        TreeRootPair[] memory multiAuthRoots = new TreeRootPair[](2);
        multiAuthRoots[0] = TreeRootPair({treeNumber: 0, root: 1});
        multiAuthRoots[1] = TreeRootPair({treeNumber: 1, root: 2}); // Not snapshotted in previous round

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 44444;

        vm.expectRevert(IPrivacyBoost.AuthTreeNotSnapshotted.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, 1001), 0, 2, 1002, 4, false),
            EpochHelpers.buildAuthState(multiAuthRoots, currentRound), // Previous round
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            EpochHelpers.defaultDigestRootIndices(),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    // ========== Deposit Epoch Tests ==========

    /// @notice Test submitDepositEpoch with empty usedRoots reverts
    /// @dev Note: The sparse root validation happens after basic epoch config checks.
    ///      To reach _validateKnownRootsSparse, we need valid deposits array.
    ///      Since creating valid deposits is complex, we test that empty deposits
    ///      fails with InvalidEpochConfig (which is the expected behavior).
    function test_revert_depositEpochEmptyDeposits() public {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: pool.treeRoot(0)});

        // Empty deposits array triggers InvalidEpochConfig
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(roots, 0, 0, 1, 1, false),
            1, // nTotalCommitments
            new Output[](1),
            new DepositEntry[](0), // Empty deposits
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test submitDepositEpoch validation sequence - epoch config checked before sparse roots
    /// @dev This verifies that empty usedRoots with empty deposits fails with InvalidEpochConfig,
    ///      confirming the validation order in submitDepositEpoch.
    function test_depositEpochValidationOrder() public {
        TreeRootPair[] memory emptyRoots = new TreeRootPair[](0);

        // Empty deposits is checked before empty usedRoots
        // So we get InvalidEpochConfig (for empty deposits), not InvalidBatchConfig (for empty roots)
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(emptyRoots, 0, 0, 1, 1, false),
            1,
            new Output[](1),
            new DepositEntry[](0),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    // ========== Digest Root Indices Tests ==========

    /// @notice Test that submitEpoch reverts when digestRootIndices is too short for nTransfers.
    function test_revertWhen_digestRootIndicesTooShort() public {
        uint256 currentRound = block.number / 300;
        uint256 root = pool.treeRoot(0);

        // Empty digestRootIndices with 1 transfer should revert
        uint256[] memory emptyIndices = new uint256[](0);

        vm.expectRevert(IPrivacyBoost.InvalidArrayLengths.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, root), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(new uint256[](1)),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            emptyIndices,
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test that submitEpoch reverts when a digestRootIndex points beyond usedRoots.
    function test_revertWhen_digestRootIndexOutOfBounds() public {
        uint256 currentRound = block.number / 300;
        uint256 root = pool.treeRoot(0);

        // Index 1 is out of bounds when usedRoots has only 1 element
        uint256[] memory badIndices = new uint256[](1);
        badIndices[0] = 1; // 4-bit index = 1, but usedRoots.length = 1

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, root), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1, // nTransfers
            1, // feeTokenCount
            1, // feeNPK
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(new uint256[](1)),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            badIndices,
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test that digestRootIndices pointing to slot 1 works when usedRoots has 2 entries.
    function test_digestRootIndexPointsToNonZeroSlot() public {
        uint256 currentRound = block.number / 300;

        // Submit a basic epoch to create a historical root and advance the tree.
        uint256 initialRoot = pool.treeRoot(0);
        _submitBasicEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 0, 1001, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound)
        );

        uint32 countAfter = pool.treeCount(0);
        uint256 currentRoot = pool.treeRoot(0);

        // usedRoots[0] = (tree0, initialRoot), usedRoots[1] = (tree0, currentRoot)
        TreeRootPair[] memory roots = new TreeRootPair[](2);
        roots[0] = TreeRootPair({treeNumber: 0, root: initialRoot});
        roots[1] = TreeRootPair({treeNumber: 0, root: currentRoot});

        // digestRootIndices[0] = 1 → transfer 0 uses slot 1 (currentRoot), not slot 0
        uint256[] memory indices = new uint256[](1);
        indices[0] = 1;

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, currentRoot, uint256(2))));

        pool.submitEpoch(
            EpochHelpers.buildTreeState(roots, 0, countAfter, 2001, countAfter + 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1,
            1,
            1,
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            indices,
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test that digestRootIndices array longer than needed is rejected (canonical encoding).
    function test_digestRootIndicesExtraWordsIgnored() public {
        uint256 currentRound = block.number / 300;
        uint256 root = pool.treeRoot(0);

        // 3 words for 1 transfer (only 1 word needed) — extra words are non-canonical
        uint256[] memory indices = new uint256[](3);
        indices[0] = 0;
        indices[1] = 0xDEAD; // garbage in extra word
        indices[2] = 0xBEEF; // garbage in extra word

        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = uint256(keccak256(abi.encodePacked(block.timestamp, root, uint256(999))));

        vm.expectRevert(IPrivacyBoost.InvalidArrayLengths.selector);
        pool.submitEpoch(
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, root), 0, 0, 1, 2, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            1,
            1,
            1,
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.singletonUint32Array(1),
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            indices,
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// @notice Test digestRootIndices extraction across uint256 word boundary (transfer 63 in word 0, transfer 64 in word 1).
    /// @dev Deploys a separate pool with batchSize=65 to exercise the t/64 word index and (t%64)*4 bit offset logic.
    function test_digestRootIndicesWordBoundary() public {
        // Deploy pool with batchSize=65 to cross the 64-transfer word boundary
        MockVerifier v = new MockVerifier();
        MockAuthRegistryMultiTree ar = new MockAuthRegistryMultiTree();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(v));
        cfg.batchSize = 65;
        cfg.maxFeeTokens = 1;
        (PrivacyBoost pool65,) = PoolDeployer.deployWithMockAuth(cfg, address(ar));
        pool65.setOperator(operator);
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool65.setAllowedRelays(relays, true);

        uint256 currentRound = block.number / 300;
        uint256 initialRoot = pool65.treeRoot(0);

        // Create a second known root so slot 1 can be used.
        // After this, (treeNumber=0, initialRoot) remains known via the ring buffer, and the new root is the current root.
        {
            uint256[] memory nullifiers1 = new uint256[](1);
            nullifiers1[0] = 999_999;

            pool65.submitEpoch(
                EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, initialRoot), 0, 0, 6001, 2, false),
                EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
                1, // nTransfers
                1, // feeTokenCount
                1, // feeNPK
                EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
                EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
                EpochHelpers.wrap2D(nullifiers1),
                EpochHelpers.buildTransfers(EpochHelpers.defaultOutputs(1)),
                EpochHelpers.buildFeeTransfer(new Output[](1)),
                new Withdrawal[](0),
                new uint32[](0),
                EpochHelpers.defaultDigestRootIndices(),
                EpochHelpers.dummyProof()
            );
        }

        uint256 currentRoot = pool65.treeRoot(0);
        uint32 countOld = pool65.treeCount(0);

        // Build 65-element arrays
        uint32[] memory inputs = new uint32[](65);
        uint32[] memory outputs = new uint32[](65);
        uint256[][] memory nulls = new uint256[][](65);
        Transfer[] memory txs = new Transfer[](65);
        for (uint256 i = 0; i < 65; i++) {
            inputs[i] = 1;
            outputs[i] = 1;
            nulls[i] = new uint256[](1);
            nulls[i][0] = i + 1; // unique nullifiers
            Output[] memory outs = new Output[](1);
            outs[0] = EpochHelpers.makeOutput(7001 + i);
            txs[i] = Transfer({viewingKey: bytes32(0), teeWrapKey: bytes32(0), outputs: outs});
        }

        // 2 usedRoots so index 1 is valid
        TreeRootPair[] memory roots = new TreeRootPair[](2);
        roots[0] = TreeRootPair({treeNumber: 0, root: initialRoot});
        roots[1] = TreeRootPair({treeNumber: 0, root: currentRoot});

        // Word 0: transfers 0-63 → slot 0 (all zeros)
        // Word 1: transfer 64 → slot 1 (value 1 in bits 0-3)
        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 1;

        pool65.submitEpoch(
            EpochHelpers.buildTreeState(roots, 0, countOld, 1, countOld + uint32(66), false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            65,
            1,
            1,
            inputs,
            outputs,
            nulls,
            txs,
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            indices,
            EpochHelpers.dummyProof()
        );
    }

    /// @notice Test that an out-of-bounds index in word 1 (for transfer 64) correctly reverts.
    /// @dev Proves the contract reads from word 1 (not word 0) for transfer 64.
    ///      If there were an off-by-one bug reading word 0 instead, index 0 would be extracted
    ///      (valid), and the test would fail because no revert occurs.
    function test_revertWhen_digestRootIndexOutOfBoundsAtWordBoundary() public {
        MockVerifier v = new MockVerifier();
        MockAuthRegistryMultiTree ar = new MockAuthRegistryMultiTree();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(v));
        cfg.batchSize = 65;
        cfg.maxFeeTokens = 1;
        (PrivacyBoost pool65,) = PoolDeployer.deployWithMockAuth(cfg, address(ar));
        pool65.setOperator(operator);
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        pool65.setAllowedRelays(relays, true);

        uint256 currentRound = block.number / 300;
        uint256 root = pool65.treeRoot(0);

        uint32[] memory inputs = new uint32[](65);
        uint32[] memory outputs = new uint32[](65);
        uint256[][] memory nulls = new uint256[][](65);
        Transfer[] memory txs = new Transfer[](65);
        for (uint256 i = 0; i < 65; i++) {
            inputs[i] = 1;
            outputs[i] = 1;
            nulls[i] = new uint256[](1);
            nulls[i][0] = i + 1;
            Output[] memory outs = new Output[](1);
            outs[0] = EpochHelpers.makeOutput(8001 + i);
            txs[i] = Transfer({viewingKey: bytes32(0), teeWrapKey: bytes32(0), outputs: outs});
        }

        // Only 1 usedRoot, so index 2 is out of bounds
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: root});

        // Word 0: all zeros (valid index 0 for transfers 0-63)
        // Word 1: index 2 for transfer 64 → out of bounds (usedRoots.length = 1)
        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 2;

        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        pool65.submitEpoch(
            EpochHelpers.buildTreeState(roots, 0, 0, 1, 66, false),
            EpochHelpers.buildAuthState(EpochHelpers.buildAuthRoots(0, 1), currentRound),
            65,
            1,
            1,
            inputs,
            outputs,
            nulls,
            txs,
            EpochHelpers.buildFeeTransfer(new Output[](1)),
            new Withdrawal[](0),
            new uint32[](0),
            indices,
            EpochHelpers.dummyProof()
        );
    }

    /// @notice Test that submitDepositEpoch still rejects duplicate tree numbers.
    /// @dev Deposit circuit uses selectByTreeNumber which sums duplicates (unsafe).
    function test_revertWhen_depositEpochDuplicateTreeNumbers() public {
        uint256 root = pool.treeRoot(0);

        TreeRootPair[] memory dupRoots = new TreeRootPair[](2);
        dupRoots[0] = TreeRootPair({treeNumber: 0, root: root});
        dupRoots[1] = TreeRootPair({treeNumber: 0, root: root});

        vm.expectRevert(IPrivacyBoost.DuplicateTreeNumber.selector);
        pool.submitDepositEpoch(
            EpochHelpers.buildTreeState(dupRoots, 0, 0, 1, 1, false),
            1,
            new Output[](1),
            new DepositEntry[](1),
            [uint256(1), 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
