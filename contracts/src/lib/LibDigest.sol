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

import {Output, Withdrawal} from "src/interfaces/IStructs.sol";
import {DOMAIN_NOTE, DOMAIN_DEPOSIT_REQUEST, DIGEST_HALF_BITS} from "src/interfaces/Constants.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";

/// @title LibDigest
/// @notice Digest and hash computation for transaction authorization
library LibDigest {
    string internal constant TRANSFER_DOMAIN = "PB:TRANSFER:v1";
    string internal constant DEPOSIT_DOMAIN = "PB:DEPOSIT:v1";
    string internal constant WITHDRAW_DOMAIN = "PB:WITHDRAW:v1";
    string internal constant FORCED_WITHDRAW_DOMAIN = "PB:FORCED_WITHDRAW:v1";

    /// @notice Compute transfer approval digest
    /// @dev Digest = keccak256(abi.encode(TRANSFER_DOMAIN, chainId, pool, root, nullifiers, outputs, viewingKey, teeWrapKey)).
    ///      Split into hi/lo for circuit field compatibility.
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param root The note tree root the transfer is authorized against
    /// @param nullifiers The input nullifiers (spent notes)
    /// @param outputs The output metadata (commitments + ciphertexts)
    /// @param viewingKey Blinded sender viewing key included in the digest
    /// @param teeWrapKey Wrapped key for the TEE included in the digest
    /// @return hi Upper DIGEST_HALF_BITS bits of the digest
    /// @return lo Lower DIGEST_HALF_BITS bits of the digest
    function computeTransferDigest(
        uint256 chainId,
        address pool,
        uint256 root,
        uint256[] memory nullifiers,
        Output[] memory outputs,
        bytes32 viewingKey,
        bytes32 teeWrapKey
    ) external pure returns (uint256 hi, uint256 lo) {
        bytes32 digest = keccak256(
            abi.encode(TRANSFER_DOMAIN, chainId, pool, root, nullifiers, outputs, viewingKey, teeWrapKey)
        );
        hi = uint256(digest) >> DIGEST_HALF_BITS;
        lo = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
    }

    /// @notice Compute withdrawal approval digest
    /// @dev Digest = keccak256(
    ///          abi.encode(WITHDRAW_DOMAIN, chainId, pool, root, nullifiers, outputs, withdrawal, viewingKey, teeWrapKey)
    ///      ).
    ///      Split into hi/lo for circuit field compatibility.
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param root The note tree root the withdrawal is authorized against
    /// @param nullifiers The input nullifiers (spent notes)
    /// @param outputs The output metadata (commitments + ciphertexts)
    /// @param withdrawal The public withdrawal details (recipient, token, amount)
    /// @param viewingKey Blinded sender viewing key included in the digest
    /// @param teeWrapKey Wrapped key for the TEE included in the digest
    /// @return hi Upper DIGEST_HALF_BITS bits of the digest
    /// @return lo Lower DIGEST_HALF_BITS bits of the digest
    function computeWithdrawalDigest(
        uint256 chainId,
        address pool,
        uint256 root,
        uint256[] memory nullifiers,
        Output[] memory outputs,
        Withdrawal calldata withdrawal,
        bytes32 viewingKey,
        bytes32 teeWrapKey
    ) external pure returns (uint256 hi, uint256 lo) {
        bytes32 digest = keccak256(
            abi.encode(WITHDRAW_DOMAIN, chainId, pool, root, nullifiers, outputs, withdrawal, viewingKey, teeWrapKey)
        );
        hi = uint256(digest) >> DIGEST_HALF_BITS;
        lo = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
    }

    /// @notice Compute forced withdrawal digest
    /// @dev Digest = keccak256(abi.encode(FORCED_WITHDRAW_DOMAIN, chainId, pool, root, nullifiers, withdrawal)).
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param root The note tree root the forced withdrawal is authorized against
    /// @param nullifiers The input nullifiers (spent notes)
    /// @param withdrawal The public withdrawal details (recipient, token, amount)
    /// @return digest The computed digest
    function computeForcedWithdrawalDigest(
        uint256 chainId,
        address pool,
        uint256 root,
        uint256[] calldata nullifiers,
        Withdrawal calldata withdrawal
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(FORCED_WITHDRAW_DOMAIN, chainId, pool, root, nullifiers, withdrawal));
    }

    /// @notice Compute the storage key for a forced withdrawal request
    /// @dev requestKey = uint256(keccak256(abi.encodePacked(requester, commitmentsHash))).
    /// @param requester The address that initiated the request
    /// @param commitmentsHash The commitments hash for the request batch
    /// @return requestKey The computed request key
    function computeRequestKey(address requester, bytes32 commitmentsHash) external pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(requester, commitmentsHash)));
    }

    /// @notice Compute withdrawal commitment: Poseidon(DOMAIN_NOTE, to, tokenId, amount)
    /// @param to The withdrawal recipient
    /// @param tokenId The compact token ID
    /// @param amount The withdrawal amount (gross)
    /// @return commitment The Poseidon note commitment
    function computeWithdrawalCommitment(address to, uint16 tokenId, uint96 amount) external pure returns (uint256) {
        return Poseidon2T4.hash4(DOMAIN_NOTE, uint256(uint160(to)), uint256(tokenId), uint256(amount));
    }

    /// @notice Compute deposit request ID for circuit compatibility
    /// @dev depositRequestId = Poseidon2T4.hash8(
    ///          DOMAIN_DEPOSIT_REQUEST, chainId, uint256(uint160(pool)), uint256(uint160(depositor)),
    ///          tokenId, totalAmount, nonce, commitmentsHash
    ///      ).
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param depositor The depositor address
    /// @param tokenId The compact token ID
    /// @param totalAmount The total deposit amount (sum of hidden per-output amounts)
    /// @param nonce The depositor nonce used for uniqueness
    /// @param commitmentsHash Sequential Poseidon hash of all commitments in the request
    /// @return depositRequestId The computed deposit request ID
    function computeDepositRequestId(
        uint256 chainId,
        address pool,
        address depositor,
        uint16 tokenId,
        uint96 totalAmount,
        uint32 nonce,
        uint256 commitmentsHash
    ) external pure returns (uint256) {
        return Poseidon2T4.hash8(
            DOMAIN_DEPOSIT_REQUEST,
            chainId,
            uint256(uint160(pool)),
            uint256(uint160(depositor)),
            uint256(tokenId),
            uint256(totalAmount),
            uint256(nonce),
            commitmentsHash
        );
    }

    /// @notice Sequential hash of commitments: Hash(Hash(...Hash(0, c0), c1), ..., cN)
    /// @param commitments The commitments to hash in order
    /// @return commitmentsHash The resulting sequential Poseidon hash
    function computeCommitmentsHash(uint256[] calldata commitments) external pure returns (uint256 commitmentsHash) {
        commitmentsHash = 0;
        for (uint256 i = 0; i < commitments.length; ++i) {
            commitmentsHash = Poseidon2T4.hash2(commitmentsHash, commitments[i]);
        }
    }

    /// @notice Incremental step for sequential hashing: newHash = Hash(prevHash, commitment)
    /// @param prevHash The previous hash value
    /// @param commitment The next commitment to include
    /// @return newHash The updated sequential Poseidon hash
    function computeCommitmentsHashStep(uint256 prevHash, uint256 commitment) external pure returns (uint256 newHash) {
        newHash = Poseidon2T4.hash2(prevHash, commitment);
    }
}
