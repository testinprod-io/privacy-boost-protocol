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

/// @dev Poseidon domain separators prevent hash collisions between different contexts.
///      Each domain tag creates a unique hash space for its specific use case.
uint256 constant DOMAIN_ACCOUNTID = 1;        // Used by circuits only: account ID derivation
uint256 constant DOMAIN_NOTE = 2;             // Note commitment hashing
uint256 constant DOMAIN_NULLIFIER = 3;        // Used by circuits only: nullifier derivation
uint256 constant DOMAIN_REG_LEAF = 4;         // AuthRegistry leaf hash
uint256 constant DOMAIN_REG_NODE = 5;         // AuthRegistry internal node hash
uint256 constant DOMAIN_APPROVE = 6;          // Used by circuits only: EdDSA approval message hash
uint256 constant DOMAIN_DEPOSIT_REQUEST = 7;  // Deposit request ID derivation
uint256 constant DOMAIN_MPK = 8;              // Used by circuits only: master public key derivation

uint8 constant TOKEN_TYPE_ERC20 = 0;

/// @dev Tree configuration shared by PrivacyBoost and AuthRegistry.
///      MERKLE_DEPTH=20 supports ~1M leaves per tree.
///      MAX_*_ROOTS_PER_PROOF = sparse root capacity included in a proof.
///      MAX_*_TREE_NUMBER = maximum global tree identifier that fits in 15 bits.
uint8 constant MERKLE_DEPTH = 20;
uint8 constant MAX_NOTE_ROOTS_PER_PROOF = 16;
uint8 constant MAX_AUTH_ROOTS_PER_PROOF = 16;
uint16 constant MAX_NOTE_TREE_NUMBER = 32767;
uint16 constant MAX_AUTH_TREE_NUMBER = 32767;
uint256 constant ROOT_HISTORY_SIZE = 64;

/// @dev Precomputed zero roots for empty Merkle trees at depth 20.
///      MERKLE_ZERO_ROOT uses hash2(left, right) for note commitments.
///      AUTH_ZERO_ROOT uses hash3(DOMAIN_REG_NODE, left, right) for auth registry.
uint256 constant MERKLE_ZERO_ROOT = 12912536786691007423957206067517486813236154886763950786309034005218474477397;
uint256 constant AUTH_ZERO_ROOT = 5126366598568957508996612635770875836246285197448927819410732545299241365093;

/// @dev Bit width for splitting keccak256 digest into hi/lo halves (circuit field compatibility)
uint8 constant DIGEST_HALF_BITS = 128;

/// @dev Number of bits per slot in packed counts field (CountOld, CountNew, Rollover, NTransfers, FeeTokenCount)
uint8 constant COUNT_BITS_PER_SLOT = 32;

/// @dev Number of slots in packed counts field
uint8 constant COUNT_PACKED_SLOTS = 5;

struct PointG1 {
    uint256 x;
    uint256 y;
}

struct PointG2 {
    uint256 x0;
    uint256 x1;
    uint256 y0;
    uint256 y1;
}

struct VerifyingKey {
    PointG1 alpha;
    PointG2 betaNeg;
    PointG2 gammaNeg;
    PointG2 deltaNeg;
    uint256[] icX;
    uint256[] icY;
}
