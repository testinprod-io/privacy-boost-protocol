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

import {Output, Transfer, EpochTreeState, AuthSnapshotState, TreeRootPair} from "src/interfaces/IStructs.sol";

library EpochHelpers {
    function dummyProof() internal pure returns (uint256[8] memory) {
        return [uint256(1), 2, 3, 4, 5, 6, 7, 8];
    }

    function singletonUint32Array(uint32 val) internal pure returns (uint32[] memory arr) {
        arr = new uint32[](1);
        arr[0] = val;
    }

    function wrap2D(uint256[] memory arr) internal pure returns (uint256[][] memory result) {
        result = new uint256[][](1);
        result[0] = arr;
    }

    function buildTransfers(Output[] memory outputs) internal pure returns (Transfer[] memory result) {
        result = new Transfer[](1);
        result[0] = Transfer({viewingKey: bytes32(0), teeWrapKey: bytes32(0), outputs: outputs});
    }

    function buildFeeTransfer(Output[] memory outputs) internal pure returns (Transfer memory) {
        return Transfer({viewingKey: bytes32(0), teeWrapKey: bytes32(0), outputs: outputs});
    }

    function buildUsedRoots(uint256 treeNumber, uint256 root) internal pure returns (TreeRootPair[] memory roots) {
        roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: treeNumber, root: root});
    }

    function buildAuthRoots(uint256 treeNumber, uint256 root) internal pure returns (TreeRootPair[] memory roots) {
        roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: treeNumber, root: root});
    }

    function buildTreeState(
        TreeRootPair[] memory usedRoots,
        uint256 activeTreeNumber,
        uint32 countOld,
        uint256 rootNew,
        uint32 countNew,
        bool rollover
    ) internal pure returns (EpochTreeState memory) {
        return EpochTreeState({
            usedRoots: usedRoots,
            activeTreeNumber: activeTreeNumber,
            countOld: countOld,
            rootNew: rootNew,
            countNew: countNew,
            rollover: rollover
        });
    }

    function buildAuthState(TreeRootPair[] memory usedAuthRoots, uint256 round)
        internal
        pure
        returns (AuthSnapshotState memory)
    {
        return AuthSnapshotState({usedAuthRoots: usedAuthRoots, authSnapshotRound: round});
    }

    function defaultOutputs(uint256 n) internal pure returns (Output[] memory outputs) {
        outputs = new Output[](n);
        for (uint256 i = 0; i < n; i++) {
            outputs[i] = makeOutput(7001 + i);
        }
    }

    function makeOutput(uint256 commitment) internal pure returns (Output memory) {
        return Output({
            commitment: commitment,
            receiverWrapKey: bytes32(0),
            ct0: bytes32(0),
            ct1: bytes32(0),
            ct2: bytes32(0),
            ct3: bytes16(0)
        });
    }

    /// @dev Returns default digestRootIndices: single word with all indices pointing to slot 0.
    function defaultDigestRootIndices() internal pure returns (uint256[] memory indices) {
        indices = new uint256[](1);
        indices[0] = 0;
    }
}
