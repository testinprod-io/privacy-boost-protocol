// Copyright (c) 2026 Sunnyside Labs Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package frontend

import "math/big"

// =============================================================================
// Circuit constants and domains
// =============================================================================
//
// This file centralizes constants that define circuit sizing defaults, range-check bit lengths,
// and Poseidon domain separators.
//
// What these constants are:
// - Default sizes used by tools/tests to pick a circuit shape (depths, max tree counts).
// - Bit-lengths used for range checks (`api.ToBinary` / `AssertIsNBits`) across circuits.
// - Domain separators used as the first input(s) to Poseidon hashes.
//
// What these constants are NOT:
// - They are not "protocol parameters" enforced by the circuit unless referenced from `Define`.
// - Changing a default does not change constraints unless the circuit shape is compiled with it.
const (
	// =============================================================================
	// Default circuit sizing
	// =============================================================================

	// DefaultNoteDepth is the default depth for note commitment trees.
	DefaultNoteDepth = 20

	// NullifierTreeNumberMultiplier defines the multiplier for encoding tree number in nullifier domain.
	// Tree number is encoded as: domain = domainNullifier + treeNumber * NullifierTreeNumberMultiplier.
	// Value 256 (2^8) provides clear separation between domains while keeping the combined value small.
	NullifierTreeNumberMultiplier = 256

	// MaxNoteRootsPerProof is the maximum number of note roots carried in a single proof.
	MaxNoteRootsPerProof = 16

	// =============================================================================
	// Bit lengths for range checks
	// =============================================================================
	//
	// These are a single source of truth for `ToBinary` / `AssertIsNBits` usage across circuits.

	// BoolBits is the bit length for boolean flags (0/1).
	BoolBits = 1

	// CountBits is the bit length for counters like NTransfers, FeeTokenCount, CountOld/CountNew.
	CountBits = 32

	// TokenIDBits is the bit length for token identifiers.
	TokenIDBits = 16

	// FeeBpsBits is the bit length for fee rates (basis points).
	FeeBpsBits = 16

	// AmountBits is the bit length for note values and fee amounts.
	// Also used for value sums, consistent with the contract's uint96 amount type.
	AmountBits = 96

	// FeeRemainderBits is the bit length for `x mod 10_000` remainder bounds (since 10_000 < 2^14).
	FeeRemainderBits = 14

	// =============================================================================
	// Fee math
	// =============================================================================

	// FeeBpsDenominator is the divisor used for basis-point fee rates.
	FeeBpsDenominator = 10_000

	// =============================================================================
	// Auth registry sizing
	// =============================================================================

	// DefaultAuthDepth is the default depth for auth registry trees.
	DefaultAuthDepth = 20

	// TreeNumberBitsPerSlot is the number of bits per packed tree number (15 bits × 16 slots = 240 bits).
	TreeNumberBitsPerSlot = 15

	// MaxAuthRootsPerProof is the maximum number of auth roots carried in a single proof.
	MaxAuthRootsPerProof = 16

	// NoteTreeNumberBits is the bit length for global note tree identifiers.
	NoteTreeNumberBits = TreeNumberBitsPerSlot

	// AuthTreeNumberBits is the bit length for global auth tree identifiers.
	AuthTreeNumberBits = TreeNumberBitsPerSlot

	// MaxNoteTreeNumber is the maximum valid note tree identifier (15-bit, inclusive).
	MaxNoteTreeNumber = (1 << NoteTreeNumberBits) - 1 // 32767

	// MaxAuthTreeNumber is the maximum valid auth tree identifier (15-bit, inclusive).
	MaxAuthTreeNumber = (1 << AuthTreeNumberBits) - 1 // 32767

	// CountsPackedSlots is the number of values in the packed counts field.
	CountsPackedSlots = 5

	// CountsPackedBitsPerSlot is the number of bits per slot in packed counts (32 bits × 5 slots = 160 bits).
	CountsPackedBitsPerSlot = 32
)

var (
	// =============================================================================
	// Poseidon domain separators
	// =============================================================================
	//
	// These constants are used to domain-separate Poseidon hashes by prepending a fixed first input.
	// They are field elements represented as `*big.Int` to keep allocation explicit and stable.

	// domainAccountId domain-separates hashes derived from a user's account key.
	// Used by account-key-related circuits/helpers when hashing account-scoped identifiers.
	domainAccountId = big.NewInt(1)

	// domainNote domain-separates note-related hashes (NPK/commitment).
	// Used by circuits that compute:
	// - NPK = Poseidon(domainNote, MPK, noteRnd)
	// - Commitment = Poseidon(domainNote, NPK, tokenId, value)
	domainNote = big.NewInt(2)

	// domainNullifier domain-separates nullifier derivation:
	// Nullifier = Poseidon(domainNullifier + treeNumber*NullifierTreeNumberMultiplier, nullifyingKey, noteLeafIndex).
	domainNullifier = big.NewInt(3)

	// domainRegLeaf domain-separates auth registry leaf hashing.
	// Leaves bind the spender account key, auth key, and policy fields (owner/expiry/flags).
	domainRegLeaf = big.NewInt(4)

	// domainRegNode domain-separates internal auth registry Merkle nodes.
	// Used by `computeDomainRoot` when hashing auth path elements.
	domainRegNode = big.NewInt(5)

	// domainApprove domain-separates the approval message hash verified by EdDSA.
	// Used by circuits to bind signatures to an on-chain digest (hi/lo).
	domainApprove = big.NewInt(6)

	// domainDepositRequest domain-separates the deposit request id digest.
	// Used by the deposit circuit to bind public request ids to (chainId, pool, depositor, token, amount, nonce, commitmentsHash).
	domainDepositRequest = big.NewInt(7)

	// domainMPK domain-separates master public key derivation:
	// MPK = Poseidon(domainMPK, accountId, nullifyingKey).
	domainMPK = big.NewInt(8)
)
