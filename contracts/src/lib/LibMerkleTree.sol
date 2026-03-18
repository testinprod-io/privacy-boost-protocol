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

import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";

/// @title LibMerkleTree
/// @notice External library for Merkle tree operations
/// @dev Extracted from PrivacyBoost to reduce contract size
library LibMerkleTree {
    /// @notice Compute the zero root for an empty Merkle tree
    /// @param depth The depth of the Merkle tree
    /// @return The root of an empty tree with the given depth
    function computeZeroRoot(uint8 depth) external pure returns (uint256) {
        uint256 current = 0;
        for (uint256 i = 0; i < depth; ++i) {
            current = Poseidon2T4.hash2(current, current);
        }
        return current;
    }
}
