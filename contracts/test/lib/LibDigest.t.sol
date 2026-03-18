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

import {LibDigest} from "src/lib/LibDigest.sol";
import {Output, Withdrawal} from "src/interfaces/IStructs.sol";

contract LibDigestTest is Test {
    uint256 constant CHAIN_ID = 1;
    address constant POOL = address(0x1234);
    uint256 constant ROOT = 0xABCD;
    uint256 constant NULLIFIER = 0x1111;
    uint256 constant DEPOSIT_REQUEST_ID = 0x2222;

    function _singleNullifier() internal pure returns (uint256[] memory) {
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = NULLIFIER;
        return nullifiers;
    }

    function _singleOutput(uint256 commitment) internal pure returns (Output[] memory) {
        Output[] memory outputs = new Output[](1);
        outputs[0] = Output({
            commitment: commitment,
            receiverWrapKey: bytes32(0),
            ct0: bytes32(0),
            ct1: bytes32(0),
            ct2: bytes32(0),
            ct3: bytes16(0)
        });
        return outputs;
    }

    function _dummyWithdrawal() internal pure returns (Withdrawal memory) {
        return Withdrawal({to: address(0xBEEF), tokenId: 1, amount: 1000 ether});
    }

    // ========== Transfer Digest ==========

    function test_computeTransferDigest_returnsSplitHash() public {
        uint256[] memory nullifiers = _singleNullifier();
        Output[] memory outputs = _singleOutput(123456);

        (uint256 hi, uint256 lo) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, ROOT, nullifiers, outputs, bytes32(0), bytes32(0));

        bytes32 expectedDigest =
            keccak256(abi.encode("PB:TRANSFER:v1", CHAIN_ID, POOL, ROOT, nullifiers, outputs, bytes32(0), bytes32(0)));

        assertEq(hi, uint256(expectedDigest) >> 128);
        assertEq(lo, uint256(expectedDigest) & ((uint256(1) << 128) - 1));
    }

    function test_computeTransferDigest_differentInputsProduceDifferentDigests() public {
        uint256[] memory nullifiers1 = _singleNullifier();
        uint256[] memory nullifiers2 = new uint256[](1);
        nullifiers2[0] = NULLIFIER + 1;
        Output[] memory outputs = _singleOutput(123456);

        (uint256 hi1, uint256 lo1) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, ROOT, nullifiers1, outputs, bytes32(0), bytes32(0));
        (uint256 hi2, uint256 lo2) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, ROOT, nullifiers2, outputs, bytes32(0), bytes32(0));

        assertTrue(hi1 != hi2 || lo1 != lo2);
    }

    // ========== Withdrawal Digest ==========

    function test_computeWithdrawalDigest_returnsSplitHash() public {
        uint256[] memory nullifiers = _singleNullifier();
        Output[] memory outputs = _singleOutput(123456);
        Withdrawal memory withdrawal = _dummyWithdrawal();

        (uint256 hi, uint256 lo) = LibDigest.computeWithdrawalDigest(
            CHAIN_ID, POOL, ROOT, nullifiers, outputs, withdrawal, bytes32(0), bytes32(0)
        );

        bytes32 expectedDigest = keccak256(
            abi.encode("PB:WITHDRAW:v1", CHAIN_ID, POOL, ROOT, nullifiers, outputs, withdrawal, bytes32(0), bytes32(0))
        );

        assertEq(hi, uint256(expectedDigest) >> 128);
        assertEq(lo, uint256(expectedDigest) & ((uint256(1) << 128) - 1));
    }

    function test_computeWithdrawalDigest_differentFromTransferDigest() public {
        uint256[] memory nullifiers = _singleNullifier();
        Output[] memory outputs = _singleOutput(123456);
        Withdrawal memory withdrawal = _dummyWithdrawal();

        (uint256 transferHi, uint256 transferLo) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, ROOT, nullifiers, outputs, bytes32(0), bytes32(0));
        (uint256 withdrawHi, uint256 withdrawLo) = LibDigest.computeWithdrawalDigest(
            CHAIN_ID, POOL, ROOT, nullifiers, outputs, withdrawal, bytes32(0), bytes32(0)
        );

        assertTrue(transferHi != withdrawHi || transferLo != withdrawLo);
    }

    // ========== Forced Withdrawal Digest ==========

    function test_computeForcedWithdrawalDigest_returnsFullHash() public {
        uint256[] memory nullifiers = new uint256[](2);
        nullifiers[0] = 0x1111;
        nullifiers[1] = 0x2222;
        Withdrawal memory withdrawal = _dummyWithdrawal();

        bytes32 digest = LibDigest.computeForcedWithdrawalDigest(CHAIN_ID, POOL, ROOT, nullifiers, withdrawal);

        bytes32 expected = keccak256(abi.encode("PB:FORCED_WITHDRAW:v1", CHAIN_ID, POOL, ROOT, nullifiers, withdrawal));

        assertEq(digest, expected);
    }

    function test_computeForcedWithdrawalDigest_differentNullifiersProduceDifferentDigests() public {
        uint256[] memory nullifiers1 = new uint256[](1);
        nullifiers1[0] = 0x1111;

        uint256[] memory nullifiers2 = new uint256[](1);
        nullifiers2[0] = 0x2222;

        Withdrawal memory withdrawal = _dummyWithdrawal();

        bytes32 digest1 = LibDigest.computeForcedWithdrawalDigest(CHAIN_ID, POOL, ROOT, nullifiers1, withdrawal);
        bytes32 digest2 = LibDigest.computeForcedWithdrawalDigest(CHAIN_ID, POOL, ROOT, nullifiers2, withdrawal);

        assertTrue(digest1 != digest2);
    }

    // ========== Request Key ==========

    function test_computeRequestKey_returnsConsistentResult() public {
        address requester = address(0xBEEF);
        bytes32 commitmentsHash = keccak256("test");

        uint256 key1 = LibDigest.computeRequestKey(requester, commitmentsHash);
        uint256 key2 = LibDigest.computeRequestKey(requester, commitmentsHash);

        assertEq(key1, key2);
    }

    function test_computeRequestKey_differentInputsProduceDifferentKeys() public {
        address requester1 = address(0xBEEF);
        address requester2 = address(0xCAFE);
        bytes32 commitmentsHash = keccak256("test");

        uint256 key1 = LibDigest.computeRequestKey(requester1, commitmentsHash);
        uint256 key2 = LibDigest.computeRequestKey(requester2, commitmentsHash);

        assertTrue(key1 != key2);
    }

    function test_computeRequestKey_matchesExpectedFormula() public {
        address requester = address(0xBEEF);
        bytes32 commitmentsHash = keccak256("test");

        uint256 key = LibDigest.computeRequestKey(requester, commitmentsHash);
        uint256 expected = uint256(keccak256(abi.encodePacked(requester, commitmentsHash)));

        assertEq(key, expected);
    }

    // ========== Withdrawal Commitment ==========

    function test_computeWithdrawalCommitment_returnsNonZero() public {
        address to = address(0xBEEF);
        uint16 tokenId = 1;
        uint96 amount = 1000 ether;

        uint256 commitment = LibDigest.computeWithdrawalCommitment(to, tokenId, amount);

        assertTrue(commitment != 0);
    }

    function test_computeWithdrawalCommitment_differentInputsProduceDifferentCommitments() public {
        uint256 commitment1 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 1, 1000 ether);
        uint256 commitment2 = LibDigest.computeWithdrawalCommitment(address(0xCAFE), 1, 1000 ether);
        uint256 commitment3 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 2, 1000 ether);
        uint256 commitment4 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 1, 2000 ether);

        assertTrue(commitment1 != commitment2);
        assertTrue(commitment1 != commitment3);
        assertTrue(commitment1 != commitment4);
    }

    function test_computeWithdrawalCommitment_sameInputsProduceSameCommitment() public {
        uint256 commitment1 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 1, 1000 ether);
        uint256 commitment2 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 1, 1000 ether);

        assertEq(commitment1, commitment2);
    }

    // ========== Deposit Request ID ==========

    function test_computeDepositRequestId_returnsNonZero() public {
        uint256 requestId = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 0, 12345);

        assertTrue(requestId != 0);
    }

    function test_computeDepositRequestId_differentNoncesProduceDifferentIds() public {
        uint256 id1 = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 0, 12345);
        uint256 id2 = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 1, 12345);

        assertTrue(id1 != id2);
    }

    function test_computeDepositRequestId_sameInputsProduceSameId() public {
        uint256 id1 = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 0, 12345);
        uint256 id2 = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 0, 12345);

        assertEq(id1, id2);
    }

    // ========== Domain Separation ==========

    function test_digestDomainSeparation_allDomainsProduceDifferentDigests() public {
        uint256[] memory nullifiers = _singleNullifier();
        Output[] memory outputs = _singleOutput(123456);
        Withdrawal memory withdrawal = _dummyWithdrawal();

        (uint256 transferHi,) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, ROOT, nullifiers, outputs, bytes32(0), bytes32(0));
        (uint256 withdrawHi,) = LibDigest.computeWithdrawalDigest(
            CHAIN_ID, POOL, ROOT, nullifiers, outputs, withdrawal, bytes32(0), bytes32(0)
        );
        bytes32 forcedDigest = LibDigest.computeForcedWithdrawalDigest(CHAIN_ID, POOL, ROOT, nullifiers, withdrawal);

        assertTrue(transferHi != withdrawHi);
        assertTrue(bytes32(transferHi << 128) != forcedDigest);
    }

    // ========== Commitments Hash ==========

    function test_computeCommitmentsHash_array_returnsSequentialHash() public {
        uint256[] memory commitments = new uint256[](3);
        commitments[0] = 100;
        commitments[1] = 200;
        commitments[2] = 300;

        uint256 hashResult = LibDigest.computeCommitmentsHash(commitments);

        // Manually compute expected: Hash(Hash(Hash(0, 100), 200), 300)
        uint256 step1 = LibDigest.computeCommitmentsHashStep(0, 100);
        uint256 step2 = LibDigest.computeCommitmentsHashStep(step1, 200);
        uint256 step3 = LibDigest.computeCommitmentsHashStep(step2, 300);

        assertEq(hashResult, step3);
    }

    function test_computeCommitmentsHash_incremental_matchesArray() public {
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        uint256 arrayHash = LibDigest.computeCommitmentsHash(commitments);

        uint256 incrementalHash = 0;
        incrementalHash = LibDigest.computeCommitmentsHashStep(incrementalHash, 111);
        incrementalHash = LibDigest.computeCommitmentsHashStep(incrementalHash, 222);

        assertEq(arrayHash, incrementalHash);
    }

    function test_computeCommitmentsHash_emptyArray_returnsZero() public {
        uint256[] memory commitments = new uint256[](0);
        uint256 hashResult = LibDigest.computeCommitmentsHash(commitments);
        assertEq(hashResult, 0);
    }

    function test_computeCommitmentsHash_differentOrderProducesDifferentHash() public {
        uint256[] memory commitments1 = new uint256[](2);
        commitments1[0] = 100;
        commitments1[1] = 200;

        uint256[] memory commitments2 = new uint256[](2);
        commitments2[0] = 200;
        commitments2[1] = 100;

        uint256 hash1 = LibDigest.computeCommitmentsHash(commitments1);
        uint256 hash2 = LibDigest.computeCommitmentsHash(commitments2);

        assertTrue(hash1 != hash2);
    }
}
