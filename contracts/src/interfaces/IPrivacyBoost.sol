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

import {
    Output,
    Transfer,
    Withdrawal,
    DepositCiphertext,
    DepositEntry,
    EpochTreeState,
    AuthSnapshotState,
    TreeRootPair
} from "src/interfaces/IStructs.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";

interface IEpochVerifier {
    /// @notice Verify an epoch circuit Groth16 proof
    /// @dev Returns true on success; may revert on malformed inputs depending on implementation.
    /// @param maxTransfers Circuit parameter: maximum number of transfers (batch size)
    /// @param maxInputsPerTransfer Circuit parameter: maximum inputs per transfer
    /// @param maxOutputsPerTransfer Circuit parameter: maximum outputs per transfer
    /// @param proof Groth16 proof (8 field elements)
    /// @param publicInputs Flattened public inputs array for the circuit
    /// @return valid True if the proof is valid
    function verifyEpoch(
        uint32 maxTransfers,
        uint32 maxInputsPerTransfer,
        uint32 maxOutputsPerTransfer,
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}

interface IDepositVerifier {
    /// @notice Verify a deposit circuit Groth16 proof
    /// @dev Returns true on success; may revert on malformed inputs depending on implementation.
    /// @param batchSize Circuit parameter: maximum number of deposits processed in the batch
    /// @param proof Groth16 proof (8 field elements)
    /// @param publicInputs Flattened public inputs array for the circuit
    /// @return valid True if the proof is valid
    function verifyDeposit(uint32 batchSize, uint256[8] calldata proof, uint256[] calldata publicInputs)
        external
        view
        returns (bool);
}

interface IForcedWithdrawVerifier {
    /// @notice Verify a forced withdrawal circuit Groth16 proof
    /// @dev Returns true on success; may revert on malformed inputs depending on implementation.
    /// @param maxInputs Circuit parameter: maximum number of inputs supported
    /// @param proof Groth16 proof (8 field elements)
    /// @param publicInputs Flattened public inputs array for the circuit
    /// @return valid True if the proof is valid
    function verifyForcedWithdraw(uint32 maxInputs, uint256[8] calldata proof, uint256[] calldata publicInputs)
        external
        view
        returns (bool);
}

/// @title IPrivacyBoost
/// @notice Interface for epoch-based private transfer pool
interface IPrivacyBoost {
    // ============ Errors ============

    /// @notice Thrown when caller is not an allowed relay
    error NotAllowedRelay();

    /// @notice Thrown when caller is not the operator
    error NotOperator();

    /// @notice Thrown when operator address is zero
    error InvalidOperatorAddress();

    /// @notice Thrown when epoch state validation fails
    error InvalidEpochState();

    /// @notice Thrown when array lengths do not match
    error InvalidArrayLengths();

    /// @notice Thrown when epoch configuration is invalid (batch size, fee token count)
    error InvalidEpochConfig();

    /// @notice Thrown when deposit validation fails
    error InvalidDeposit();

    /// @notice Thrown when withdrawal validation fails
    error InvalidWithdrawal();

    /// @notice Thrown when withdrawalSlots are not strictly increasing (sorted and unique)
    /// @param index The index of the offending slot
    /// @param prev The previous slot value
    /// @param curr The current slot value
    error WithdrawalSlotsNotStrictAscending(uint256 index, uint32 prev, uint32 curr);

    /// @notice Thrown when token type is not supported
    /// @param tokenType The unsupported token type
    error TokenNotSupported(uint8 tokenType);

    /// @notice Thrown when fee exceeds maximum allowed (100%)
    error FeeExceedsMaximum();

    /// @notice Thrown when a provided root is not found in history
    error RootNotKnown();

    /// @notice Thrown when a nullifier has already been spent
    error InvalidNullifierSet();

    /// @notice Thrown when a nullifier or commitment violates the active/inactive zero-padding invariant
    error InvalidSlotPadding();

    /// @notice Thrown when packed data has non-zero bits in padding slots (non-canonical encoding)
    error NonCanonicalEncoding();

    /// @notice Thrown when a deposit request ID already exists
    error DepositAlreadyExists();

    /// @notice Thrown when a deposit has already been processed
    error DepositAlreadyProcessed();

    /// @notice Thrown when caller is not the depositor
    error NotDepositor();

    /// @notice Thrown when trying to cancel before the delay period
    error CancelTooEarly();

    /// @notice Thrown when forced withdrawal request does not exist
    error ForcedWithdrawalNotRequested();

    /// @notice Thrown when forced withdrawal has already been requested for a commitment.
    /// Commitment collisions between different users are cryptographically negligible.
    error ForcedWithdrawalAlreadyRequested();

    /// @notice Thrown when trying to execute forced withdrawal before the delay period
    error ForcedWithdrawalTooEarly();

    /// @notice Thrown when forced withdrawal parameters do not match the stored request
    error ForcedWithdrawalMismatch();

    /// @notice Thrown when caller is not the original requester
    error NotRequester();

    /// @notice Thrown when caller is neither the requester nor the account owner
    error NotRequesterOrOwner();

    /// @notice Thrown when batch configuration is invalid (empty roots or >16 roots)
    error InvalidBatchConfig();

    /// @notice Thrown when too many distinct trees in sparse array (>16)
    error TooManyDistinctTrees();

    /// @notice Thrown when tree number exceeds 15-bit maximum (32767)
    error TreeNumberOverflow();

    /// @notice Thrown when auth tree number doesn't exist
    error InvalidAuthTreeNumber();

    /// @notice Thrown when trying to use an auth tree that wasn't snapshotted in a previous round
    error AuthTreeNotSnapshotted();

    /// @notice Thrown when auth snapshot round is invalid
    error InvalidAuthSnapshotRound();

    /// @notice Thrown when treasury is not set but withdraw fee is enabled
    error TreasuryNotSet();

    /// @notice Thrown when tokenRegistry address is zero or not a contract
    error InvalidTokenRegistryAddress();

    /// @notice Thrown when authRegistry address is zero or not a contract
    error InvalidAuthRegistryAddress();

    /// @notice Thrown when maxBatchSize is set to zero
    error MaxBatchSizeCannotBeZero();

    /// @notice Thrown when maxInputsPerTransfer is set to zero
    error MaxInputsPerTransferCannotBeZero();

    /// @notice Thrown when maxOutputsPerTransfer is set to zero
    error MaxOutputsPerTransferCannotBeZero();

    /// @notice Thrown when maxFeeTokens is set to zero
    error MaxFeeTokensCannotBeZero();

    /// @notice Thrown when maxForcedInputs is set to zero
    error MaxForcedInputsCannotBeZero();

    /// @notice Thrown when merkleDepth is out of supported range for zero hash preimages
    /// @param value The invalid merkleDepth value
    /// @param min The minimum allowed value
    /// @param max The maximum allowed value
    error MerkleDepthOutOfRange(uint8 value, uint8 min, uint8 max);

    /// @notice Thrown when authSnapshotInterval is out of valid range
    /// @param value The invalid value
    /// @param min The minimum allowed value
    /// @param max The maximum allowed value
    error AuthSnapshotIntervalOutOfRange(uint256 value, uint256 min, uint256 max);

    /// @notice Thrown when an authSnapshotInterval update is already pending
    error AuthSnapshotIntervalUpdatePending();

    /// @notice Thrown when trying to set authSnapshotInterval to the current value
    error AuthSnapshotIntervalNoChange();

    /// @notice Thrown when a fee-on-transfer token is detected (received amount differs from requested)
    /// @param requested The amount requested to deposit
    /// @param received The actual amount received after transfer
    error FeeOnTransferNotSupported(uint256 requested, uint256 received);

    /// @notice Thrown when duplicate nullifiers are provided in the same request
    error DuplicateNullifier();

    /// @notice Thrown when duplicate input commitments are provided in the same request
    error DuplicateInputCommitment();

    /// @notice Thrown when duplicate tree numbers are provided in a sparse roots array
    error DuplicateTreeNumber();

    /// @notice Thrown when a sparse roots array contains an exact duplicate (treeNumber, root) pair
    /// @dev Epoch allows duplicate tree numbers (with different roots) but does not need exact duplicate pairs.
    error DuplicateTreeRootPair();

    // ============ Events ============

    /// @notice Emitted when a transfer/withdrawal epoch is submitted
    /// @param treeNum The tree that received the outputs
    /// @param rootNew The new root value
    /// @param countOld The leaf count before this epoch (0 if rollover to new tree)
    /// @param countNew The new leaf count
    event EpochSubmitted(uint256 indexed treeNum, uint256 indexed rootNew, uint32 countOld, uint32 countNew);

    /// @notice Emitted when a deposit epoch is submitted
    /// @param treeNum The tree that received the deposits
    /// @param rootNew The new root value
    /// @param countOld The leaf count before this epoch (0 if rollover to new tree)
    /// @param countNew The new leaf count
    event DepositEpochSubmitted(uint256 indexed treeNum, uint256 indexed rootNew, uint32 countOld, uint32 countNew);

    /// @notice Emitted when the active tree advances to a new tree
    /// @param oldTreeNumber The previous tree number
    /// @param newTreeNumber The new tree number
    event TreeAdvanced(uint256 oldTreeNumber, uint256 newTreeNumber);

    /// @notice Emitted when an auth tree is lazily snapshotted
    /// @param round The snapshot round number
    /// @param treeNum The auth tree number
    /// @param root The captured root
    event AuthTreeSnapshotted(uint256 indexed round, uint256 indexed treeNum, uint256 root);

    /// @notice Emitted when fee rates are updated
    /// @param withdrawFeeBps The new withdraw fee in basis points
    event FeesUpdated(uint16 withdrawFeeBps);

    /// @notice Emitted when authSnapshotInterval is updated
    /// @param oldValue The previous authSnapshotInterval value
    /// @param newValue The new authSnapshotInterval value
    event AuthSnapshotIntervalUpdated(uint256 oldValue, uint256 newValue);

    /// @notice Emitted when an authSnapshotInterval update is scheduled for a future round boundary
    /// @param oldInterval The current active interval
    /// @param newInterval The interval that will become active
    /// @param effectiveBlock The block number at which the new interval becomes active
    /// @param effectiveRound The round number at which the new interval becomes active
    /// @param newVersion The schedule version that will become active
    event AuthSnapshotIntervalUpdateScheduled(
        uint256 oldInterval, uint256 newInterval, uint256 effectiveBlock, uint256 effectiveRound, uint256 newVersion
    );

    /// @notice Emitted when a scheduled authSnapshotInterval update becomes active
    /// @param oldInterval The previous active interval
    /// @param newInterval The new active interval
    /// @param startBlock The start block for the new schedule segment
    /// @param startRound The start round for the new schedule segment
    /// @param version The new active schedule version
    event AuthSnapshotIntervalActivated(
        uint256 oldInterval, uint256 newInterval, uint256 startBlock, uint256 startRound, uint256 version
    );

    /// @notice Emitted when a relay address is allowed or disallowed
    /// @param relay The relay address
    /// @param allowed Whether the relay is allowed
    event RelayUpdated(address relay, bool allowed);

    /// @notice Emitted when the operator address is updated
    /// @param oldOperator The previous operator address
    /// @param newOperator The new operator address
    event OperatorUpdated(address indexed oldOperator, address indexed newOperator);

    /// @notice Emitted when a deposit is requested
    /// @param depositRequestId The unique identifier for the deposit request
    /// @param depositor The address that made the deposit
    /// @param tokenId The token ID from the registry
    /// @param totalAmount The total deposit amount (sum of hidden individual amounts)
    /// @param commitmentCount The number of commitments in this request
    /// @param commitmentsHash Sequential Poseidon hash of all commitments
    /// @param commitments The note commitments (for indexing)
    /// @param ciphertexts The encrypted deposit payloads for TEE decryption
    event DepositRequested(
        uint256 indexed depositRequestId,
        address indexed depositor,
        uint16 tokenId,
        uint96 totalAmount,
        uint16 commitmentCount,
        uint256 commitmentsHash,
        uint256[] commitments,
        DepositCiphertext[] ciphertexts
    );

    /// @notice Emitted when a deposit is cancelled
    /// @param depositRequestId The deposit request that was cancelled
    event DepositCancelled(uint256 indexed depositRequestId);

    /// @notice Emitted when a forced withdrawal is requested
    /// @param requester The address that made the request
    /// @param withdrawalTo The address to receive the withdrawal
    /// @param tokenId The token ID from the registry
    /// @param amount The withdrawal amount (gross, before fee)
    /// @param nullifiers The nullifiers of the notes being spent
    /// @param inputCommitments The commitments of the notes being spent
    event ForcedWithdrawalRequested(
        address indexed requester,
        address indexed withdrawalTo,
        uint16 tokenId,
        uint96 amount,
        uint256[] nullifiers,
        uint256[] inputCommitments
    );

    /// @notice Emitted when a forced withdrawal is executed
    /// @param withdrawalTo The address that received the withdrawal
    /// @param tokenId The token ID from the registry
    /// @param amount The net amount received (after fee deduction)
    /// @param nullifiers The nullifiers of the notes that were spent
    /// @param inputCommitments The commitments of the notes that were spent
    event ForcedWithdrawalExecuted(
        address indexed withdrawalTo, uint16 tokenId, uint96 amount, uint256[] nullifiers, uint256[] inputCommitments
    );

    /// @notice Emitted when a forced withdrawal request is cancelled
    /// @param nullifiers The nullifiers from the cancelled request
    /// @param inputCommitments The commitments from the cancelled request
    event ForcedWithdrawalCancelled(uint256[] nullifiers, uint256[] inputCommitments);

    /// @notice Emitted when the treasury address is updated
    /// @param oldTreasury The previous treasury address
    /// @param newTreasury The new treasury address
    event TreasuryUpdated(address oldTreasury, address newTreasury);

    /// @notice Emitted when the epoch verifier is updated
    /// @param oldVerifier The previous verifier address
    /// @param newVerifier The new verifier address
    event EpochVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /// @notice Emitted when the deposit verifier is updated
    /// @param oldVerifier The previous verifier address
    /// @param newVerifier The new verifier address
    event DepositVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    // ============ Functions ============

    /// @notice Initialize the contract
    /// @param initialOwner The address of the initial owner
    /// @param epochVerifier_ The epoch verifier contract address
    /// @param depositVerifier_ The deposit verifier contract address
    /// @param forcedVerifier_ The forced withdrawal verifier contract address
    /// @param withdrawFeeBps_ Withdraw fee in basis points
    /// @param treasury_ The treasury address for fee collection
    /// @param authSnapshotInterval_ Block interval between auth root snapshots
    function initialize(
        address initialOwner,
        address epochVerifier_,
        address depositVerifier_,
        address forcedVerifier_,
        uint16 withdrawFeeBps_,
        address treasury_,
        uint256 authSnapshotInterval_
    ) external;

    /// @notice Set the operator address
    /// @dev Only callable by owner. Operator can manage relays and operational parameters.
    /// @param operator_ The new operator address
    function setOperator(address operator_) external;

    /// @notice Set allowed relay addresses
    /// @dev Only callable by operator. Relays can submit epochs on behalf of users.
    /// @param relays Array of relay addresses to update
    /// @param allowed Whether to allow or disallow the relays
    function setAllowedRelays(address[] calldata relays, bool allowed) external;

    /// @notice Set fee rates
    /// @dev Only callable by owner. Fees are in basis points (1/10000).
    /// @param withdrawFeeBps_ Withdraw fee in basis points
    function setFees(uint16 withdrawFeeBps_) external;

    /// @notice Set the epoch verifier contract
    /// @dev Only callable by owner.
    /// @param verifier_ The new epoch verifier address
    function setEpochVerifier(address verifier_) external;

    /// @notice Set the deposit verifier contract
    /// @dev Only callable by owner.
    /// @param verifier_ The new deposit verifier address
    function setDepositVerifier(address verifier_) external;

    /// @notice Set the treasury address for fee collection
    /// @dev Only callable by owner.
    /// @param treasury_ The new treasury address
    function setTreasury(address treasury_) external;

    /// @notice Set the auth snapshot interval
    /// @dev Only callable by operator.
    /// @param authSnapshotInterval_ The new auth snapshot interval
    function setAuthSnapshotInterval(uint256 authSnapshotInterval_) external;

    /// @notice Snapshot auth tree roots for the current round
    /// @dev Only callable by an allowed relay. This establishes auth snapshots ahead of
    ///      permissionless flows (e.g., forced withdrawals) without introducing a first-caller race.
    /// @param treeNums Auth tree numbers to snapshot
    function snapshotAuthTrees(uint256[] calldata treeNums) external;

    /// @notice Submit an epoch with mixed transfers and withdrawals
    /// @dev Only callable by allowed relays. Supports N inputs and M outputs per transfer slot.
    ///      The circuit uses IsWithdrawal flag to select the appropriate fee rate.
    /// @param treeState Tree state with sparse roots (usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover)
    /// @param authState Auth snapshot state with sparse roots (usedAuthRoots, authSnapshotRound)
    /// @param nTransfers Number of active transfers
    /// @param feeTokenCount Number of active fee tokens
    /// @param feeNPK Fee recipient's Note Public Key
    /// @param inputsPerTransfer Number of inputs for each transfer [maxTransfers]
    /// @param outputsPerTransfer Number of outputs for each transfer [maxTransfers]
    /// @param nullifiers Nullifiers per transfer slot [maxTransfers][maxInputsPerTransfer]
    /// @param transfers Transfer metadata with shared keys and outputs per transfer
    /// @param feeTransfer Fee transfer metadata with shared keys and fee outputs
    /// @param withdrawals Withdrawal details (sorted by slot index)
    /// @param withdrawalSlots Transfer slot indices for each withdrawal (sorted ascending)
    /// @param digestRootIndices Packed 4-bit indices into usedRoots for per-transfer digest root selection
    /// @param proof Groth16 proof
    function submitEpoch(
        EpochTreeState calldata treeState,
        AuthSnapshotState calldata authState,
        uint32 nTransfers,
        uint32 feeTokenCount,
        uint256 feeNPK,
        uint32[] calldata inputsPerTransfer,
        uint32[] calldata outputsPerTransfer,
        uint256[][] calldata nullifiers,
        Transfer[] calldata transfers,
        Transfer calldata feeTransfer,
        Withdrawal[] calldata withdrawals,
        uint32[] calldata withdrawalSlots,
        uint256[] calldata digestRootIndices,
        uint256[8] calldata proof
    ) external;

    /// @notice Step 1 of 2-step deposit: Request a deposit with one or more commitments
    /// @dev Tokens are transferred from caller to contract. Deposits are fee-free.
    ///      Only standard ERC20 tokens are supported. Fee-on-transfer tokens will revert.
    ///      Rebasing tokens (stETH, AMPL) are NOT supported and may cause fund loss.
    ///      Individual commitment amounts are hidden; only totalAmount is public.
    /// @param _tokenId TokenRegistry token ID
    /// @param _totalAmount Total deposit amount (sum of hidden individual amounts)
    /// @param _commitments Note commitments for each output
    /// @param _ciphertexts Encrypted deposit payloads for TEE decryption
    /// @return depositRequestId The unique identifier for the deposit request
    function requestDeposit(
        uint16 _tokenId,
        uint96 _totalAmount,
        uint256[] calldata _commitments,
        DepositCiphertext[] calldata _ciphertexts
    ) external returns (uint256 depositRequestId);

    /// @notice Cancel a pending deposit and refund tokens
    /// @dev Can only be called by the depositor after cancelDelay blocks.
    /// @param _depositRequestId The deposit to cancel
    function cancelDeposit(uint256 _depositRequestId) external;

    /// @notice Step 2 of 2-step deposit: Process batch of pending deposits
    /// @dev Only callable by allowed relays. Deposits are fee-free.
    ///      TEE prover verifies deposit data without requiring user approval signatures.
    /// @param treeState Tree state with sparse roots (usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover)
    /// @param nTotalCommitments Total number of commitments across all deposits
    /// @param outputs Output metadata per commitment
    /// @param deposits Array of deposit entries (depositRequestId references)
    /// @param proof Groth16 proof
    function submitDepositEpoch(
        EpochTreeState calldata treeState,
        uint32 nTotalCommitments,
        Output[] calldata outputs,
        DepositEntry[] calldata deposits,
        uint256[8] calldata proof
    ) external;

    /// @notice Step 1 of 2-step forced withdrawal: Request forced withdrawal with proof
    /// @dev Proof verifies ownership. After forcedWithdrawalDelay, execute can be called.
    ///      Fee is calculated at execution time based on withdrawFeeBps.
    ///      SpenderAccountId is exposed as public input so the account owner can cancel
    ///      malicious requests via AuthRegistry.ownerOf(spenderAccountId).
    /// @param knownRoots Sparse tree roots used in this batch
    /// @param authState Auth snapshot state with sparse roots (usedAuthRoots, authSnapshotRound)
    /// @param spenderAccountId Account ID for owner lookup (public input in ZK proof)
    /// @param nullifiers Nullifiers of the notes being spent
    /// @param inputCommitments Commitments of the notes being spent
    /// @param withdrawal Withdrawal details (amount is gross, before fee)
    /// @param proof Groth16 proof of note ownership
    function requestForcedWithdrawal(
        TreeRootPair[] calldata knownRoots,
        AuthSnapshotState calldata authState,
        uint256 spenderAccountId,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        Withdrawal calldata withdrawal,
        uint256[8] calldata proof
    ) external;

    /// @notice Step 2 of 2-step forced withdrawal: Execute forced withdrawal
    /// @dev Can only be called after forcedWithdrawalDelay blocks.
    ///      Will fail if nullifiers have been spent by a normal transfer.
    /// @param nullifiers Nullifiers from the original request
    /// @param inputCommitments Commitments from the original request
    function executeForcedWithdrawal(uint256[] calldata nullifiers, uint256[] calldata inputCommitments) external;

    /// @notice Cancel a pending forced withdrawal request
    /// @dev Can be called after forcedWithdrawalDelay by either:
    ///      - the original requester, or
    ///      - the account owner (resolved via AuthRegistry.ownerOf(spenderAccountId)).
    /// @param nullifiers Nullifiers from the original request
    /// @param inputCommitments Commitments from the original request
    function cancelForcedWithdrawal(uint256[] calldata nullifiers, uint256[] calldata inputCommitments) external;

    /// @notice Check if a root is known for a specific tree
    /// @dev For finalized trees, only the final root is valid.
    ///      For the current tree, checks the root history ring buffer.
    /// @param treeNum The tree number to check
    /// @param root_ The root to verify
    /// @return True if the root is known
    function isKnownTreeRoot(uint256 treeNum, uint256 root_) external view returns (bool);

    // ============ View Functions (State Variables) ============

    /// @notice Current active tree number
    function currentTreeNumber() external view returns (uint256);

    /// @notice Get the root of a specific tree
    /// @param treeNum The tree number
    /// @return The tree root
    function treeRoot(uint256 treeNum) external view returns (uint256);

    /// @notice Get the leaf count of a specific tree
    /// @param treeNum The tree number
    /// @return The number of leaves in the tree
    function treeCount(uint256 treeNum) external view returns (uint32);

    /// @notice Get a historical root from a tree's history
    /// @param treeNum The tree number
    /// @param idx The history index
    /// @return The historical root
    function treeRootHistory(uint256 treeNum, uint256 idx) external view returns (uint256);

    /// @notice Get the cursor position in the root history ring buffer
    /// @param treeNum The tree number
    /// @return The cursor position
    function treeRootHistoryCursor(uint256 treeNum) external view returns (uint256);

    /// @notice Check if a nullifier has been spent
    /// @param nullifier The nullifier to check
    /// @return True if spent
    function nullifierSpent(uint256 nullifier) external view returns (bool);

    /// @notice Check if an address is an allowed relay
    /// @param relay The address to check
    /// @return True if allowed
    function allowedRelays(address relay) external view returns (bool);

    /// @notice Withdraw fee rate in basis points
    function withdrawFeeBps() external view returns (uint16);

    /// @notice Maximum number of inputs for forced withdrawals
    function maxForcedInputs() external view returns (uint32);

    /// @notice Get a pending deposit by request ID
    /// @param depositRequestId The deposit request ID
    /// @return depositor The depositor address
    /// @return tokenId The token ID
    /// @return totalAmount The total deposit amount
    /// @return requestBlock The block number when deposit was requested
    /// @return nonce The depositor's nonce at request time
    /// @return commitmentCount The number of commitments in this request
    /// @return commitmentsHash Sequential Poseidon hash of all commitments
    function pendingDeposits(uint256 depositRequestId)
        external
        view
        returns (
            address depositor,
            uint16 tokenId,
            uint96 totalAmount,
            uint64 requestBlock,
            uint32 nonce,
            uint16 commitmentCount,
            uint256 commitmentsHash
        );

    /// @notice Check if a deposit has been processed
    /// @param depositRequestId The deposit request ID
    /// @return True if processed
    function processedDeposits(uint256 depositRequestId) external view returns (bool);

    /// @notice Get deposit nonce for an address
    /// @param depositor The depositor address
    /// @return The current nonce
    function depositNonces(address depositor) external view returns (uint32);

    /// @notice Get a forced withdrawal request by key
    /// @param requestKey The request key
    /// @return requestBlock The block number when request was made
    /// @return requester The requester address
    /// @return withdrawalTo The withdrawal recipient address
    /// @return tokenId The token ID
    /// @return amount The withdrawal amount (gross)
    /// @return withdrawFeeBps The withdraw fee at request time
    /// @return inputCount The number of input notes
    /// @return spenderAccountId The account ID for owner lookup
    /// @return nullifiersHash Hash of the nullifiers
    /// @return commitmentsHash Hash of the commitments
    function forcedWithdrawalRequests(uint256 requestKey)
        external
        view
        returns (
            uint64 requestBlock,
            address requester,
            address withdrawalTo,
            uint16 tokenId,
            uint96 amount,
            uint16 withdrawFeeBps,
            uint8 inputCount,
            uint256 spenderAccountId,
            bytes32 nullifiersHash,
            bytes32 commitmentsHash
        );

    /// @notice Get the request key for a commitment
    /// @param commitment The note commitment
    /// @return The request key (0 if not requested)
    function commitmentToRequestKey(uint256 commitment) external view returns (uint256);

    /// @notice Get auth snapshot root
    /// @param round The round number
    /// @param treeNum The auth tree number
    /// @return The snapshot root
    function authSnapshots(uint256 round, uint256 treeNum) external view returns (uint256);

    /// @notice The most recent round for which a snapshot was taken
    /// @return The latest snapshot round number
    function latestSnapshotRound() external view returns (uint256);

    /// @notice Treasury address for fee collection
    function treasury() external view returns (address);

    /// @notice Operator address for operational functions
    function operator() external view returns (address);

    // ============ Immutable Variables ============

    /// @notice Token registry contract
    function tokenRegistry() external view returns (ITokenRegistry);

    /// @notice Block interval between auth root snapshots
    /// @return The interval in blocks
    function authSnapshotInterval() external view returns (uint256);

    /// @notice Compute the current auth snapshot round (versioned schedule).
    function currentAuthSnapshotRound() external view returns (uint256);

    /// @notice Compute auth snapshot round for a given block number.
    function authSnapshotRoundAt(uint256 blockNumber) external view returns (uint256);

    /// @notice Auth snapshot interval effective at the current block.
    function currentAuthSnapshotInterval() external view returns (uint256);

    /// @notice Apply a pending auth snapshot interval update if it is due.
    function syncAuthSnapshotInterval() external;

    /// @notice Start block for the active auth snapshot schedule segment.
    function authSnapshotStartBlock() external view returns (uint256);

    /// @notice Start round for the active auth snapshot schedule segment.
    function authSnapshotStartRound() external view returns (uint256);

    /// @notice Monotonic version for the auth snapshot schedule.
    function authSnapshotScheduleVersion() external view returns (uint256);

    /// @notice Pending auth snapshot interval (0 if none).
    function pendingAuthSnapshotInterval() external view returns (uint256);

    /// @notice Block number when the pending interval becomes active (0 if none).
    function pendingAuthSnapshotEffectiveBlock() external view returns (uint256);

    /// @notice Round number when the pending interval becomes active (0 if none).
    function pendingAuthSnapshotStartRound() external view returns (uint256);

    /// @notice Auth registry contract
    function authRegistry() external view returns (IAuthRegistry);

    /// @notice Maximum number of transfer slots per epoch
    function maxBatchSize() external view returns (uint32);

    /// @notice Maximum inputs per transfer
    function maxInputsPerTransfer() external view returns (uint32);

    /// @notice Maximum outputs per transfer
    function maxOutputsPerTransfer() external view returns (uint32);

    /// @notice Maximum number of fee tokens
    function maxFeeTokens() external view returns (uint32);

    /// @notice Delay before deposits can be cancelled
    function cancelDelay() external view returns (uint256);

    /// @notice Delay before forced withdrawals can be executed
    function forcedWithdrawalDelay() external view returns (uint256);

    /// @notice Epoch verifier contract
    function epochVerifier() external view returns (IEpochVerifier);

    /// @notice Deposit verifier contract
    function depositVerifier() external view returns (IDepositVerifier);

    /// @notice Forced withdrawal verifier contract
    function forcedVerifier() external view returns (IForcedWithdrawVerifier);
}
