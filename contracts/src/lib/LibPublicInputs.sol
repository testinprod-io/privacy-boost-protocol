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

import {EpochTreeState, AuthSnapshotState, TreeRootPair} from "src/interfaces/IStructs.sol";
import {
    MAX_NOTE_ROOTS_PER_PROOF,
    MAX_AUTH_ROOTS_PER_PROOF,
    MAX_NOTE_TREE_NUMBER,
    DIGEST_HALF_BITS
} from "src/interfaces/Constants.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";

/// @title LibPublicInputs
/// @notice Construct public input arrays for ZK verifiers
library LibPublicInputs {
    /// @notice Pack count-related values into a single field element
    /// @dev Layout: CountOld | (CountNew << 32) | (Rollover << 64) | (NTransfers << 96) | (FeeTokenCount << 128)
    ///      Total: 160 bits (5 slots × 32 bits), fits within BN254's ~254-bit scalar field.
    /// @param countOld Leaf count before the epoch update
    /// @param countNew Leaf count after the epoch update
    /// @param rollover Whether the active tree rolled over to a new tree
    /// @param nTransfers Number of transfers in this epoch
    /// @param feeTokenCount Number of fee tokens used for this epoch
    /// @return packed Packed counts field element
    function packCounts(uint32 countOld, uint32 countNew, bool rollover, uint32 nTransfers, uint32 feeTokenCount)
        internal
        pure
        returns (uint256 packed)
    {
        packed = uint256(countOld);
        packed |= uint256(countNew) << 32;
        packed |= (rollover ? uint256(1) : uint256(0)) << 64;
        packed |= uint256(nTransfers) << 96;
        packed |= uint256(feeTokenCount) << 128;
    }

    /// @notice Pack sparse tree data into roots array and packed tree numbers
    /// @dev Internal helper shared by note tree and auth tree packing functions.
    ///      Tree numbers are packed as 15-bit values: packedTreeNumbers = treeNum[0] | (treeNum[1] << 15) | ...
    ///      Using 15 bits allows 16 slots × 15 bits = 240 bits, fitting in BN254's ~254-bit scalar field.
    /// @param sparse The sparse tree root pairs to pack
    /// @param maxSlots Maximum number of slots allowed (for bounds checking)
    /// @return packedTreeNumbers Packed tree numbers in a single field element
    function _packTreeData(TreeRootPair[] calldata sparse, uint256 maxSlots)
        private
        pure
        returns (uint256 packedTreeNumbers)
    {
        uint256 len = sparse.length;
        if (len > maxSlots) revert IPrivacyBoost.TooManyDistinctTrees();
        for (uint256 i = 0; i < len; ++i) {
            uint256 treeNum = sparse[i].treeNumber;
            if (treeNum > MAX_NOTE_TREE_NUMBER) revert IPrivacyBoost.TreeNumberOverflow();
            // Pack tree number into 15-bit slot
            packedTreeNumbers |= (treeNum << (i * 15));
        }
    }

    /// @notice Convert sparse tree roots to packed arrays for circuit (roots array + single packed tree numbers)
    /// @dev Separate function from auth version due to different return array sizes for type safety.
    /// @param sparse Sparse (treeNumber, root) pairs to pack
    /// @return packedRoots Fixed-size roots array padded with zeros
    /// @return packedTreeNumbers Packed 15-bit tree numbers in a single field element
    function sparseToPackedRootsWithTreeNumbers(TreeRootPair[] calldata sparse)
        internal
        pure
        returns (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers)
    {
        packedTreeNumbers = _packTreeData(sparse, MAX_NOTE_ROOTS_PER_PROOF);
        for (uint256 i = 0; i < sparse.length; ++i) {
            packedRoots[i] = sparse[i].root;
        }
    }

    /// @notice Convert sparse auth roots to packed arrays for circuit (roots array + single packed tree numbers)
    /// @dev Separate function from note version due to different return array sizes for type safety.
    /// @param sparse Sparse (treeNumber, root) pairs to pack
    /// @return packedRoots Fixed-size auth roots array padded with zeros
    /// @return packedTreeNumbers Packed 15-bit tree numbers in a single field element
    function sparseToPackedAuthRootsWithTreeNumbers(TreeRootPair[] calldata sparse)
        internal
        pure
        returns (uint256[MAX_AUTH_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers)
    {
        packedTreeNumbers = _packTreeData(sparse, MAX_AUTH_ROOTS_PER_PROOF);
        for (uint256 i = 0; i < sparse.length; ++i) {
            packedRoots[i] = sparse[i].root;
        }
    }

    /// @notice Build public inputs for epoch verification
    /// @dev Layout: [knownRoots(16), packedTreeNumbers, digestRootMask, activeTree, activeTreeRoot,
    ///              countsPacked, rootNew,
    ///              authRoots(16), packedAuthTreeNumbers,
    ///              nullifiers(maxTransfers*maxInputs), commitments(maxTransfers*maxOutputs),
    ///              digestHi(maxTransfers), digestLo(maxTransfers),
    ///              feeNPK, feeCommitments(maxFeeTokens)]
    /// @dev 2D arrays are flattened row-major: nullifiers[t][i] -> idx = t * maxInputs + i
    /// @param treeState Note tree state (sparse roots, active tree number, counts, new root)
    /// @param authState Auth snapshot state (sparse auth roots, snapshot round)
    /// @param activeTreeRoot Root of the active note tree (treeState.activeTreeNumber)
    /// @param digestRootMask Digest inclusion bitmask (circuit-defined)
    /// @param nTransfers Actual number of transfers (must be <= nullifiers.length)
    /// @param nullifiers Padded nullifier matrix [maxTransfers][maxInputsPerTransfer]
    /// @param commitmentsOut Padded output commitments matrix [maxTransfers][maxOutputsPerTransfer]
    /// @param approveDigestHi High halves of per-transfer approval digests (length = maxTransfers)
    /// @param approveDigestLo Low halves of per-transfer approval digests (length = maxTransfers)
    /// @param feeTokenCount Number of fee tokens used (<= maxFeeTokens)
    /// @param feeNPK Fee note public key for the fee receiver (circuit-defined)
    /// @param feeCommitmentsOut Fee output commitments (length = maxFeeTokens)
    /// @param maxInputsPerTransfer Circuit parameter: max inputs per transfer
    /// @param maxOutputsPerTransfer Circuit parameter: max outputs per transfer
    /// @param maxFeeTokens Circuit parameter: max fee tokens
    /// @return publicInputs Flattened public input array for epoch verification
    function buildEpochInputs(
        EpochTreeState calldata treeState,
        AuthSnapshotState calldata authState,
        uint256 activeTreeRoot,
        uint256 digestRootMask,
        uint256 nTransfers,
        uint256[][] calldata nullifiers,
        uint256[][] memory commitmentsOut,
        uint256[] memory approveDigestHi,
        uint256[] memory approveDigestLo,
        uint32 feeTokenCount,
        uint256 feeNPK,
        uint256[] memory feeCommitmentsOut,
        uint32 maxInputsPerTransfer,
        uint32 maxOutputsPerTransfer,
        uint32 maxFeeTokens
    ) external pure returns (uint256[] memory) {
        uint256 maxTransfers = nullifiers.length;
        // Layout: knownRoots(16) + packedTreeNumbers(1) + digestRootMask(1) + activeTree(1) + activeTreeRoot(1) +
        //         countsPacked(1) + rootNew(1) +
        //         authRoots(16) + packedAuthTreeNumbers(1) +
        //         nullifiers(maxTransfers * maxInputs) + commitments(maxTransfers * maxOutputs) +
        //         digestHi(maxTransfers) + digestLo(maxTransfers) +
        //         feeNPK(1) + feeCommitments(maxFeeTokens)
        uint256 totalNullifiers = maxTransfers * maxInputsPerTransfer;
        uint256 totalCommitments = maxTransfers * maxOutputsPerTransfer;
        uint256[] memory publicInputs = new uint256[](
            MAX_NOTE_ROOTS_PER_PROOF + 2 + MAX_AUTH_ROOTS_PER_PROOF + 1 + 4 + totalNullifiers + totalCommitments
                + maxTransfers * 2 + 1 + maxFeeTokens
        );
        uint256 idx;

        (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers) =
            sparseToPackedRootsWithTreeNumbers(treeState.usedRoots);
        for (uint256 i = 0; i < MAX_NOTE_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedRoots[i];
        }
        publicInputs[idx++] = packedTreeNumbers;
        publicInputs[idx++] = digestRootMask;

        publicInputs[idx++] = treeState.activeTreeNumber;
        publicInputs[idx++] = activeTreeRoot;

        // Pack counts: CountOld | (CountNew << 32) | (Rollover << 64) | (NTransfers << 96) | (FeeTokenCount << 128)
        uint256 countsPacked =
            packCounts(treeState.countOld, treeState.countNew, treeState.rollover, uint32(nTransfers), feeTokenCount);
        publicInputs[idx++] = countsPacked;
        publicInputs[idx++] = treeState.rootNew;

        (uint256[MAX_AUTH_ROOTS_PER_PROOF] memory packedAuthRoots, uint256 packedAuthTreeNumbers) =
            sparseToPackedAuthRootsWithTreeNumbers(authState.usedAuthRoots);
        for (uint256 i = 0; i < MAX_AUTH_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedAuthRoots[i];
        }
        publicInputs[idx++] = packedAuthTreeNumbers;

        // Flatten nullifiers row-major: [t][i] -> idx = t * maxInputs + i
        for (uint256 t = 0; t < maxTransfers; ++t) {
            for (uint256 i = 0; i < maxInputsPerTransfer; ++i) {
                publicInputs[idx++] = nullifiers[t][i];
            }
        }

        // Flatten commitments row-major: [t][j] -> idx = t * maxOutputs + j
        for (uint256 t = 0; t < maxTransfers; ++t) {
            for (uint256 j = 0; j < maxOutputsPerTransfer; ++j) {
                publicInputs[idx++] = commitmentsOut[t][j];
            }
        }

        // Digests (one per transfer)
        for (uint256 t = 0; t < maxTransfers; ++t) {
            publicInputs[idx++] = approveDigestHi[t];
        }
        for (uint256 t = 0; t < maxTransfers; ++t) {
            publicInputs[idx++] = approveDigestLo[t];
        }

        publicInputs[idx++] = feeNPK;
        for (uint256 i = 0; i < maxFeeTokens; ++i) {
            publicInputs[idx++] = feeCommitmentsOut[i];
        }

        return publicInputs;
    }

    /// @notice Build public inputs for deposit epoch verification
    /// @dev Layout: [chainId, poolAddress,
    ///              knownRoots(16), packedTreeNumbers,
    ///              activeTree, countOld, rootNew, countNew, rollover,
    ///              nRequests, nTotalCommitments,
    ///              depositRequestIds(maxSlots), totalAmounts(maxSlots),
    ///              commitmentCounts(maxSlots), commitmentsOut(maxSlots)]
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param treeState Note tree state (sparse roots, active tree number, counts, new root)
    /// @param nRequests Number of distinct deposit requests included
    /// @param nTotalCommitments Total number of commitments across all included requests
    /// @param depositRequestIdsPadded Deposit request IDs padded to maxSlots
    /// @param totalAmountsPadded Total amounts (per request) padded to maxSlots
    /// @param commitmentCountsPadded Commitment counts (per request) padded to maxSlots
    /// @param commitmentsOutPadded Output commitments padded to maxSlots
    /// @return publicInputs Flattened public input array for deposit verification
    function buildDepositInputs(
        uint256 chainId,
        address pool,
        EpochTreeState calldata treeState,
        uint256 nRequests,
        uint256 nTotalCommitments,
        uint256[] memory depositRequestIdsPadded,
        uint256[] memory totalAmountsPadded,
        uint256[] memory commitmentCountsPadded,
        uint256[] memory commitmentsOutPadded
    ) external pure returns (uint256[] memory) {
        uint256 maxSlots = commitmentsOutPadded.length;
        uint256[] memory publicInputs = new uint256[](MAX_NOTE_ROOTS_PER_PROOF + 10 + maxSlots * 4);
        uint256 idx;

        publicInputs[idx++] = chainId;
        publicInputs[idx++] = uint256(uint160(pool));

        (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers) =
            sparseToPackedRootsWithTreeNumbers(treeState.usedRoots);
        for (uint256 i = 0; i < MAX_NOTE_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedRoots[i];
        }
        publicInputs[idx++] = packedTreeNumbers;

        publicInputs[idx++] = treeState.activeTreeNumber;
        publicInputs[idx++] = treeState.countOld;
        publicInputs[idx++] = treeState.rootNew;
        publicInputs[idx++] = treeState.countNew;
        publicInputs[idx++] = treeState.rollover ? 1 : 0;
        publicInputs[idx++] = nRequests;
        publicInputs[idx++] = nTotalCommitments;

        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = depositRequestIdsPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = totalAmountsPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = commitmentCountsPadded[i];
        }
        for (uint256 i = 0; i < maxSlots; ++i) {
            publicInputs[idx++] = commitmentsOutPadded[i];
        }

        return publicInputs;
    }

    /// @notice Build public inputs for forced withdrawal verification
    /// @dev Layout: [knownRoots(16), packedTreeNumbers, authRoots(16), packedAuthTreeNumbers,
    ///              inputCount, spenderAccountId, nullifiers(N), inputCommitments(N),
    ///              digestHi, digestLo, withdrawalTo, tokenId, amount]
    /// @param sparseRoots Sparse (treeNumber, root) pairs to pack for note trees
    /// @param authState Auth snapshot state (sparse auth roots, snapshot round)
    /// @param inputCount Number of inputs used (must be <= nullifiersPadded.length)
    /// @param spenderAccountId Account ID used for auth lookup and authorization
    /// @param nullifiersPadded Nullifiers padded to maxInputs
    /// @param inputCommitmentsPadded Input commitments padded to maxInputs
    /// @param digest Forced-withdraw digest (will be split into hi/lo)
    /// @param withdrawalTo Withdrawal recipient
    /// @param tokenId The compact token ID
    /// @param amount The withdrawal amount (gross)
    /// @return publicInputs Flattened public input array for forced withdrawal verification
    function buildForcedWithdrawalInputs(
        TreeRootPair[] calldata sparseRoots,
        AuthSnapshotState calldata authState,
        uint256 inputCount,
        uint256 spenderAccountId,
        uint256[] calldata nullifiersPadded,
        uint256[] calldata inputCommitmentsPadded,
        bytes32 digest,
        address withdrawalTo,
        uint16 tokenId,
        uint96 amount
    ) external pure returns (uint256[] memory) {
        uint256 maxInputs = nullifiersPadded.length;
        uint256[] memory publicInputs =
            new uint256[](MAX_NOTE_ROOTS_PER_PROOF + 1 + MAX_AUTH_ROOTS_PER_PROOF + 1 + 7 + (maxInputs * 2));
        uint256 idx;

        (uint256[MAX_NOTE_ROOTS_PER_PROOF] memory packedRoots, uint256 packedTreeNumbers) =
            sparseToPackedRootsWithTreeNumbers(sparseRoots);
        for (uint256 i = 0; i < MAX_NOTE_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedRoots[i];
        }
        publicInputs[idx++] = packedTreeNumbers;

        (uint256[MAX_AUTH_ROOTS_PER_PROOF] memory packedAuthRoots, uint256 packedAuthTreeNumbers) =
            sparseToPackedAuthRootsWithTreeNumbers(authState.usedAuthRoots);
        for (uint256 i = 0; i < MAX_AUTH_ROOTS_PER_PROOF; ++i) {
            publicInputs[idx++] = packedAuthRoots[i];
        }
        publicInputs[idx++] = packedAuthTreeNumbers;

        publicInputs[idx++] = inputCount;
        publicInputs[idx++] = spenderAccountId;

        for (uint256 i = 0; i < maxInputs; ++i) {
            publicInputs[idx++] = nullifiersPadded[i];
        }
        for (uint256 i = 0; i < maxInputs; ++i) {
            publicInputs[idx++] = inputCommitmentsPadded[i];
        }

        publicInputs[idx++] = uint256(digest) >> DIGEST_HALF_BITS;
        publicInputs[idx++] = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
        publicInputs[idx++] = uint256(uint160(withdrawalTo));
        publicInputs[idx++] = uint256(tokenId);
        publicInputs[idx++] = uint256(amount);

        return publicInputs;
    }
}
