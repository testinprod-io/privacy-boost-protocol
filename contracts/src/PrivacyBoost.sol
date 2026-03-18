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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    TOKEN_TYPE_ERC20,
    MAX_NOTE_ROOTS_PER_PROOF,
    MAX_NOTE_TREE_NUMBER,
    MAX_AUTH_ROOTS_PER_PROOF,
    ROOT_HISTORY_SIZE
} from "src/interfaces/Constants.sol";
import {LibZeroHashes} from "src/lib/LibZeroHashes.sol";
import {
    Output,
    Transfer,
    Withdrawal,
    PendingDeposit,
    DepositCiphertext,
    DepositEntry,
    ForcedWithdrawalRequest,
    EpochTreeState,
    AuthSnapshotState,
    TreeRootPair
} from "src/interfaces/IStructs.sol";
import {
    IPrivacyBoost,
    IEpochVerifier,
    IDepositVerifier,
    IForcedWithdrawVerifier
} from "src/interfaces/IPrivacyBoost.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {LibPublicInputs} from "src/lib/LibPublicInputs.sol";

/// @title PrivacyBoost
/// @notice Epoch-based private transfer pool (v2)
contract PrivacyBoost is IPrivacyBoost, Ownable2StepUpgradeable, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /// @dev Basis points denominator for fee calculations (100% = 10,000 bps)
    uint256 private constant BASIS_POINTS = 10_000;

    /// @dev Maximum fee rate in basis points (10% = 1,000 bps).
    uint256 private constant MAX_FEE_BPS = 1_000;

    /// @dev Minimum authSnapshotInterval in blocks
    uint256 private constant MIN_AUTH_SNAPSHOT_INTERVAL = 10;

    /// @dev Maximum authSnapshotInterval in blocks
    uint256 private constant MAX_AUTH_SNAPSHOT_INTERVAL = 100_000;

    /// @dev BN254 scalar field modulus (same as Groth16Verifier.R / Poseidon2T4.PRIME).
    ///      Commitments must be strict field elements to avoid calldata aliasing (x and x+q hash identically).
    uint256 private constant SNARK_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @notice Token registry contract
    ITokenRegistry public immutable tokenRegistry;

    /// @notice Auth registry contract
    IAuthRegistry public immutable authRegistry;

    /// @notice Maximum number of transfer slots per epoch
    uint32 public immutable maxBatchSize;

    /// @notice Maximum inputs per transfer
    uint32 public immutable maxInputsPerTransfer;

    /// @notice Maximum outputs per transfer
    uint32 public immutable maxOutputsPerTransfer;

    /// @notice Maximum number of fee tokens
    uint32 public immutable maxFeeTokens;

    /// @notice Delay before deposits can be cancelled
    uint256 public immutable cancelDelay;

    /// @notice Delay before forced withdrawals can be executed
    uint256 public immutable forcedWithdrawalDelay;

    /// @notice Maximum number of inputs for forced withdrawals
    uint32 public immutable maxForcedInputs;

    /// @notice Note Merkle tree depth
    /// @dev Must match circuit parameter MERKLE_DEPTH.
    uint8 public immutable merkleDepth;

    /// @notice Epoch verifier contract
    IEpochVerifier public epochVerifier;

    /// @notice Deposit verifier contract
    IDepositVerifier public depositVerifier;

    /// @notice Forced withdrawal verifier contract
    IForcedWithdrawVerifier public forcedVerifier;

    /// @notice Current active tree number
    uint256 public currentTreeNumber;

    /// @notice Treasury address for fee collection
    address public treasury;

    /// @notice Operator address for operational functions
    address public operator;

    /// @notice Withdraw fee rate in basis points
    uint16 public withdrawFeeBps;

    /// @notice Block interval between auth root snapshots
    uint256 public authSnapshotInterval;

    /// @notice Get the root of a specific tree
    /// @dev Per-tree Merkle state
    mapping(uint256 treeNum => uint256 root) public treeRoot;

    /// @notice Get the leaf count of a specific tree
    mapping(uint256 treeNum => uint32 leafCount) public treeCount;

    /// @notice Get a historical root from a tree's history
    /// @dev Ring buffer for recent roots (allows proofs against slightly stale state)
    mapping(uint256 treeNum => uint256[ROOT_HISTORY_SIZE] roots) public treeRootHistory;

    /// @notice Get the cursor position in the root history ring buffer
    mapping(uint256 treeNum => uint256 cursor) public treeRootHistoryCursor;

    /// @notice Check if a nullifier has been spent
    mapping(uint256 nullifier => bool spent) public nullifierSpent;

    /// @notice Check if an address is an allowed relay
    mapping(address relay => bool allowed) public allowedRelays;

    /// @notice Get a pending deposit by request ID
    /// @dev 2-step deposit: request → (wait cancelDelay) → process or cancel
    mapping(uint256 depositRequestId => PendingDeposit deposit) public pendingDeposits;

    /// @notice Check if a deposit has been processed
    mapping(uint256 depositRequestId => bool processed) public processedDeposits;

    /// @notice Get deposit nonce for an address
    mapping(address depositor => uint32 nonce) public depositNonces;

    /// @notice Get a forced withdrawal request by key
    /// @dev 2-step forced withdrawal: request → (wait forcedWithdrawalDelay) → execute or cancel
    mapping(uint256 requestKey => ForcedWithdrawalRequest request) public forcedWithdrawalRequests;

    /// @notice Get the request key for a commitment
    mapping(uint256 commitment => uint256 requestKey) public commitmentToRequestKey;

    /// @notice Get auth snapshot root
    /// @dev Auth snapshots prevent key rotation attacks by freezing auth state per round
    mapping(uint256 round => mapping(uint256 treeNum => uint256 root)) public authSnapshots;

    /// @notice The most recent round for which a snapshot was taken
    uint256 public latestSnapshotRound;

    /// @notice Start block for the active auth snapshot schedule segment
    /// @dev Round numbers are computed as:
    ///      authSnapshotStartRound + (blockNumber - authSnapshotStartBlock) / authSnapshotInterval
    uint256 public authSnapshotStartBlock;

    /// @notice Start round for the active auth snapshot schedule segment
    uint256 public authSnapshotStartRound;

    /// @notice Monotonic version for the auth snapshot schedule
    uint256 public authSnapshotScheduleVersion;

    /// @notice Pending authSnapshotInterval value (0 if none)
    uint256 public pendingAuthSnapshotInterval;

    /// @notice Block number when the pending interval becomes active (0 if none)
    uint256 public pendingAuthSnapshotEffectiveBlock;

    /// @notice Round number when the pending interval becomes active (0 if none)
    uint256 public pendingAuthSnapshotStartRound;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address tokenRegistry_,
        address authRegistry_,
        uint32 maxBatchSize_,
        uint32 maxInputsPerTransfer_,
        uint32 maxOutputsPerTransfer_,
        uint32 maxFeeTokens_,
        uint256 cancelDelay_,
        uint256 forcedWithdrawalDelay_,
        uint32 maxForcedInputs_,
        uint8 merkleDepth_
    ) {
        if (tokenRegistry_ == address(0) || tokenRegistry_.code.length == 0) {
            revert InvalidTokenRegistryAddress();
        }
        if (authRegistry_ == address(0) || authRegistry_.code.length == 0) revert InvalidAuthRegistryAddress();
        if (maxBatchSize_ == 0) revert MaxBatchSizeCannotBeZero();
        if (maxInputsPerTransfer_ == 0) revert MaxInputsPerTransferCannotBeZero();
        if (maxOutputsPerTransfer_ == 0) revert MaxOutputsPerTransferCannotBeZero();
        if (maxFeeTokens_ == 0) revert MaxFeeTokensCannotBeZero();
        if (maxForcedInputs_ == 0) revert MaxForcedInputsCannotBeZero();
        if (merkleDepth_ == 0 || merkleDepth_ > 24) revert MerkleDepthOutOfRange(merkleDepth_, 1, 24);
        tokenRegistry = ITokenRegistry(tokenRegistry_);
        authRegistry = IAuthRegistry(authRegistry_);
        maxBatchSize = maxBatchSize_;
        maxInputsPerTransfer = maxInputsPerTransfer_;
        maxOutputsPerTransfer = maxOutputsPerTransfer_;
        maxFeeTokens = maxFeeTokens_;
        cancelDelay = cancelDelay_;
        forcedWithdrawalDelay = forcedWithdrawalDelay_;
        maxForcedInputs = maxForcedInputs_;
        merkleDepth = merkleDepth_;
        _disableInitializers();
    }

    /// @inheritdoc IPrivacyBoost
    function initialize(
        address initialOwner,
        address epochVerifier_,
        address depositVerifier_,
        address forcedVerifier_,
        uint16 withdrawFeeBps_,
        address treasury_,
        uint256 authSnapshotInterval_
    ) external initializer {
        __Ownable2Step_init();
        _transferOwnership(initialOwner);

        _validateAuthSnapshotInterval(authSnapshotInterval_);

        epochVerifier = IEpochVerifier(epochVerifier_);
        depositVerifier = IDepositVerifier(depositVerifier_);
        forcedVerifier = IForcedWithdrawVerifier(forcedVerifier_);
        treasury = treasury_;
        authSnapshotInterval = authSnapshotInterval_;
        // Initialize round schedule to match historical semantics:
        // round = block.number / authSnapshotInterval (i.e., startBlock=0, startRound=0).
        authSnapshotStartBlock = 0;
        authSnapshotStartRound = 0;
        authSnapshotScheduleVersion = 0;
        _setFees(withdrawFeeBps_);

        uint256 zeroRoot = _zeroRoot();
        currentTreeNumber = 0;
        treeRoot[0] = zeroRoot;
        treeRootHistory[0][0] = zeroRoot;
    }

    modifier onlyRelay() {
        _checkRelay();
        _;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    /// @dev Verify caller is an allowed relay
    function _checkRelay() internal view {
        if (!allowedRelays[msg.sender]) revert NotAllowedRelay();
    }

    /// @inheritdoc IPrivacyBoost
    function setOperator(address operator_) external onlyOwner {
        if (operator_ == address(0)) revert InvalidOperatorAddress();
        address oldOperator = operator;
        operator = operator_;
        emit OperatorUpdated(oldOperator, operator_);
    }

    /// @inheritdoc IPrivacyBoost
    function setAllowedRelays(address[] calldata relays, bool allowed) external onlyOperator {
        for (uint256 i = 0; i < relays.length; ++i) {
            allowedRelays[relays[i]] = allowed;
            emit RelayUpdated(relays[i], allowed);
        }
    }

    /// @inheritdoc IPrivacyBoost
    function setFees(uint16 withdrawFeeBps_) external onlyOwner {
        _setFees(withdrawFeeBps_);
    }

    /// @inheritdoc IPrivacyBoost
    function setEpochVerifier(address verifier_) external onlyOwner {
        address oldVerifier = address(epochVerifier);
        epochVerifier = IEpochVerifier(verifier_);
        emit EpochVerifierUpdated(oldVerifier, verifier_);
    }

    /// @inheritdoc IPrivacyBoost
    function setDepositVerifier(address verifier_) external onlyOwner {
        address oldVerifier = address(depositVerifier);
        depositVerifier = IDepositVerifier(verifier_);
        emit DepositVerifierUpdated(oldVerifier, verifier_);
    }

    /// @inheritdoc IPrivacyBoost
    function setTreasury(address treasury_) external onlyOwner {
        if (treasury_ == address(0) && withdrawFeeBps > 0) {
            revert TreasuryNotSet();
        }
        address oldTreasury = treasury;
        treasury = treasury_;
        emit TreasuryUpdated(oldTreasury, treasury_);
    }

    /// @notice Compute auth snapshot round for a given block number.
    /// @dev Uses a piecewise schedule so interval updates do not retroactively shift round numbering.
    function authSnapshotRoundAt(uint256 blockNumber) public view returns (uint256) {
        // Default to active schedule segment
        uint256 interval = authSnapshotInterval;
        uint256 startBlock = authSnapshotStartBlock;
        uint256 startRound = authSnapshotStartRound;

        // If a pending update is due at this block, use the pending schedule segment.
        uint256 pendingEffectiveBlock = pendingAuthSnapshotEffectiveBlock;
        if (pendingEffectiveBlock != 0 && blockNumber >= pendingEffectiveBlock) {
            interval = pendingAuthSnapshotInterval;
            startBlock = pendingEffectiveBlock;
            startRound = pendingAuthSnapshotStartRound;
        }

        if (blockNumber < startBlock) {
            // Should not happen for normal queries (startBlock is always <= current block),
            // but clamp to startRound for safety.
            return startRound;
        }

        return startRound + (blockNumber - startBlock) / interval;
    }

    /// @notice Compute the current auth snapshot round.
    function currentAuthSnapshotRound() public view returns (uint256) {
        return authSnapshotRoundAt(block.number);
    }

    /// @notice Auth snapshot interval effective at the current block.
    /// @dev This may differ from `authSnapshotInterval()` if a scheduled update is due but not yet applied.
    function currentAuthSnapshotInterval() public view returns (uint256) {
        if (pendingAuthSnapshotEffectiveBlock != 0 && block.number >= pendingAuthSnapshotEffectiveBlock) {
            return pendingAuthSnapshotInterval;
        }
        return authSnapshotInterval;
    }

    /// @notice Apply a pending auth snapshot interval update if it is due.
    /// @dev Anyone can call this to keep on-chain config in sync with the schedule.
    function syncAuthSnapshotInterval() external {
        _applyPendingAuthSnapshotIntervalIfDue();
    }

    /// @inheritdoc IPrivacyBoost
    function setAuthSnapshotInterval(uint256 authSnapshotInterval_) external onlyOperator {
        _validateAuthSnapshotInterval(authSnapshotInterval_);
        _applyPendingAuthSnapshotIntervalIfDue();

        // Only one pending update at a time (prevents ambiguous schedules).
        if (pendingAuthSnapshotEffectiveBlock != 0) revert AuthSnapshotIntervalUpdatePending();
        if (authSnapshotInterval_ == authSnapshotInterval) revert AuthSnapshotIntervalNoChange();

        (uint256 currentRound, uint256 currentRoundStartBlock) = _activeAuthSnapshotRoundAndStartBlock();
        uint256 effectiveBlock = currentRoundStartBlock + authSnapshotInterval;
        uint256 effectiveRound = currentRound + 1;

        pendingAuthSnapshotInterval = authSnapshotInterval_;
        pendingAuthSnapshotEffectiveBlock = effectiveBlock;
        pendingAuthSnapshotStartRound = effectiveRound;

        emit AuthSnapshotIntervalUpdateScheduled(
            authSnapshotInterval, authSnapshotInterval_, effectiveBlock, effectiveRound, authSnapshotScheduleVersion + 1
        );
    }

    /// @dev Validate authSnapshotInterval is within bounds
    function _validateAuthSnapshotInterval(uint256 interval) internal pure {
        if (interval < MIN_AUTH_SNAPSHOT_INTERVAL || interval > MAX_AUTH_SNAPSHOT_INTERVAL) {
            revert AuthSnapshotIntervalOutOfRange(interval, MIN_AUTH_SNAPSHOT_INTERVAL, MAX_AUTH_SNAPSHOT_INTERVAL);
        }
    }

    function _applyPendingAuthSnapshotIntervalIfDue() internal {
        uint256 effectiveBlock = pendingAuthSnapshotEffectiveBlock;
        if (effectiveBlock == 0 || block.number < effectiveBlock) return;

        uint256 oldInterval = authSnapshotInterval;
        uint256 newInterval = pendingAuthSnapshotInterval;

        authSnapshotStartBlock = effectiveBlock;
        authSnapshotStartRound = pendingAuthSnapshotStartRound;
        authSnapshotInterval = newInterval;
        authSnapshotScheduleVersion += 1;

        // Clear pending schedule
        pendingAuthSnapshotInterval = 0;
        pendingAuthSnapshotEffectiveBlock = 0;
        pendingAuthSnapshotStartRound = 0;

        emit AuthSnapshotIntervalUpdated(oldInterval, newInterval);
        emit AuthSnapshotIntervalActivated(
            oldInterval, newInterval, authSnapshotStartBlock, authSnapshotStartRound, authSnapshotScheduleVersion
        );
    }

    function _currentAuthSnapshotRoundSync() internal returns (uint256) {
        _applyPendingAuthSnapshotIntervalIfDue();
        if (block.number < authSnapshotStartBlock) return authSnapshotStartRound;
        return authSnapshotStartRound + (block.number - authSnapshotStartBlock) / authSnapshotInterval;
    }

    function _activeAuthSnapshotRoundAndStartBlock()
        internal
        view
        returns (uint256 currentRound, uint256 currentRoundStartBlock)
    {
        uint256 startBlock = authSnapshotStartBlock;
        uint256 startRound = authSnapshotStartRound;
        uint256 interval = authSnapshotInterval;

        if (block.number < startBlock) {
            return (startRound, startBlock);
        }

        uint256 elapsed = block.number - startBlock;
        uint256 offsetRounds = elapsed / interval;
        currentRound = startRound + offsetRounds;
        currentRoundStartBlock = startBlock + offsetRounds * interval;
    }

    /// @inheritdoc IPrivacyBoost
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
    ) external nonReentrant onlyRelay {
        uint32 circuitMaxTransfers = uint32(nullifiers.length);

        // Validate circuit configuration bounds
        bool invalidCircuitSize = (circuitMaxTransfers == 0) || (circuitMaxTransfers > maxBatchSize);
        bool invalidTransferCount = (nTransfers == 0) || (nTransfers > circuitMaxTransfers);
        if (invalidCircuitSize || invalidTransferCount) revert InvalidEpochConfig();

        // Validate top-level array dimensions
        bool mismatchedCountArrays =
            (inputsPerTransfer.length != circuitMaxTransfers) || (outputsPerTransfer.length != circuitMaxTransfers);
        bool mismatchedTransferArrays =
            (transfers.length != circuitMaxTransfers) || (feeTransfer.outputs.length != maxFeeTokens);
        if (mismatchedCountArrays || mismatchedTransferArrays) revert InvalidArrayLengths();

        // Derive per-transfer circuit dimensions from calldata (same pattern as circuitMaxTransfers)
        uint32 circuitMaxInputs = uint32(nullifiers[0].length);
        uint32 circuitMaxOutputs = uint32(transfers[0].outputs.length);
        if (circuitMaxInputs == 0 || circuitMaxInputs > maxInputsPerTransfer) revert InvalidEpochConfig();
        if (circuitMaxOutputs == 0 || circuitMaxOutputs > maxOutputsPerTransfer) revert InvalidEpochConfig();

        // Validate inner array dimensions and per-transfer input/output counts
        for (uint256 t = 0; t < circuitMaxTransfers; ++t) {
            if (nullifiers[t].length != circuitMaxInputs || transfers[t].outputs.length != circuitMaxOutputs) {
                revert InvalidArrayLengths();
            }
            if (t < nTransfers) {
                if (inputsPerTransfer[t] == 0 || inputsPerTransfer[t] > circuitMaxInputs) {
                    revert InvalidEpochConfig();
                }
                if (outputsPerTransfer[t] == 0 || outputsPerTransfer[t] > circuitMaxOutputs) {
                    revert InvalidEpochConfig();
                }
            } else {
                if (inputsPerTransfer[t] != 0 || outputsPerTransfer[t] != 0) revert InvalidEpochConfig();
            }
        }

        // Tree state must match on-chain state exactly to prevent proof replay or state manipulation
        if (treeState.activeTreeNumber != currentTreeNumber) revert InvalidEpochState();
        if (treeState.countOld != treeCount[treeState.activeTreeNumber]) revert InvalidEpochState();

        // Validate all sparse roots are known (ring buffer check).
        // Epoch allows duplicate tree numbers: each transfer independently selects its digest root
        // via digestRootIndices, and the circuit uses findPairMatch (OR-based, safe with duplicates).
        _validateKnownRoots(treeState.usedRoots, treeState.activeTreeNumber, true);
        // Active tree root for frontier binding comes directly from on-chain state,
        // allowing NoteKnownRoots to contain past roots for input spending.
        uint256 activeRoot = treeRoot[treeState.activeTreeNumber];
        _validateAuthKnownRootsSparse(authState.usedAuthRoots, authState.authSnapshotRound, true);

        if (feeTokenCount == 0 || feeTokenCount > maxFeeTokens) revert InvalidEpochConfig();

        // Validate digestRootIndices canonical encoding:
        // - exactly enough packed words to cover active transfers (4 bits each, 64 per word)
        // - unused 4-bit slots in the last word must be zero
        uint256 expectedDigestRootWords = (uint256(nTransfers) + 63) / 64;
        if (digestRootIndices.length != expectedDigestRootWords) revert InvalidArrayLengths();
        uint256 lastWordUsedSlots = uint256(nTransfers) & 63; // nTransfers % 64
        if (lastWordUsedSlots != 0) {
            // Ensure padding bits are zero to prevent non-canonical calldata encodings.
            if (digestRootIndices[expectedDigestRootWords - 1] >> (lastWordUsedSlots * 4) != 0) {
                revert NonCanonicalEncoding();
            }
        }

        // Count total outputs for tree capacity validation
        uint32 totalOutputs = 0;
        for (uint256 t = 0; t < nTransfers; ++t) {
            totalOutputs += outputsPerTransfer[t];
        }
        _validateTreeCapacity(treeState.countOld, treeState.countNew, totalOutputs + feeTokenCount, treeState.rollover);

        // Withdrawal slots must be strictly increasing (sorted + unique) and reference active transfers.
        _validateWithdrawalSlots(withdrawalSlots, withdrawals.length, nTransfers);

        (
            uint256[][] memory commitmentsOut,
            uint256[] memory approveDigestHi,
            uint256[] memory approveDigestLo,
            uint256 digestRootMask
        ) = _computeTransferDigests(
            inputsPerTransfer,
            outputsPerTransfer,
            nullifiers,
            transfers,
            withdrawals,
            withdrawalSlots,
            treeState.usedRoots,
            digestRootIndices,
            circuitMaxTransfers,
            nTransfers,
            circuitMaxOutputs
        );

        _validateSlotPadding(
            nullifiers,
            commitmentsOut,
            inputsPerTransfer,
            outputsPerTransfer,
            nTransfers,
            circuitMaxTransfers,
            circuitMaxInputs,
            circuitMaxOutputs
        );

        uint256[] memory feeCommitmentsOut = _buildFeeCommitments(feeTransfer, maxFeeTokens);
        uint256[] memory publicInputs = LibPublicInputs.buildEpochInputs(
            treeState,
            authState,
            activeRoot,
            digestRootMask,
            nTransfers,
            nullifiers,
            commitmentsOut,
            approveDigestHi,
            approveDigestLo,
            feeTokenCount,
            feeNPK,
            feeCommitmentsOut,
            circuitMaxInputs,
            circuitMaxOutputs,
            maxFeeTokens
        );

        epochVerifier.verifyEpoch(circuitMaxTransfers, circuitMaxInputs, circuitMaxOutputs, proof, publicInputs);

        _spendNullifiers(nullifiers, inputsPerTransfer, nTransfers);

        _processWithdrawals(withdrawals);
        _updateTreeState(treeState.activeTreeNumber, treeState.rootNew, treeState.countNew, treeState.rollover);

        emit EpochSubmitted(
            currentTreeNumber, treeState.rootNew, treeState.rollover ? 0 : treeState.countOld, treeState.countNew
        );
    }

    /// @inheritdoc IPrivacyBoost
    function requestDeposit(
        uint16 _tokenId,
        uint96 _totalAmount,
        uint256[] calldata _commitments,
        DepositCiphertext[] calldata _ciphertexts
    ) external nonReentrant returns (uint256 depositRequestId) {
        uint256 commitmentCount = _commitments.length;
        if (commitmentCount == 0 || commitmentCount > maxBatchSize) revert InvalidDeposit();
        if (_totalAmount == 0) revert InvalidDeposit();
        if (commitmentCount != _ciphertexts.length) revert InvalidArrayLengths();

        // Sequential hash binds commitment order to prevent reordering attacks
        uint256 commitmentsHash = 0;
        for (uint256 i = 0; i < commitmentCount; ++i) {
            uint256 commitment = _commitments[i];
            if (commitment == 0 || commitment >= SNARK_SCALAR_FIELD) revert InvalidDeposit();
            commitmentsHash = LibDigest.computeCommitmentsHashStep(commitmentsHash, commitment);
        }

        (uint8 tokenType, address tokenAddress,) = tokenRegistry.tokenOf(_tokenId);
        if (tokenAddress == address(0)) revert InvalidDeposit();
        if (tokenType != TOKEN_TYPE_ERC20) revert TokenNotSupported(tokenType);

        // Reject fee-on-transfer tokens to prevent accounting mismatch
        uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), _totalAmount);
        uint256 balanceAfter = IERC20(tokenAddress).balanceOf(address(this));
        if (balanceAfter - balanceBefore != _totalAmount) {
            revert FeeOnTransferNotSupported(_totalAmount, balanceAfter - balanceBefore);
        }

        uint32 nonce = depositNonces[msg.sender]++;
        depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(this), msg.sender, _tokenId, _totalAmount, nonce, commitmentsHash
        );

        if (pendingDeposits[depositRequestId].depositor != address(0)) {
            revert DepositAlreadyExists();
        }

        // forge-lint: disable-next-line(unsafe-typecast) commitmentCount <= maxBatchSize (uint32)
        pendingDeposits[depositRequestId] = PendingDeposit({
            depositor: msg.sender,
            tokenId: _tokenId,
            totalAmount: _totalAmount,
            requestBlock: uint64(block.number),
            nonce: nonce,
            commitmentCount: uint16(commitmentCount),
            commitmentsHash: commitmentsHash
        });

        emit DepositRequested(
            depositRequestId,
            msg.sender,
            _tokenId,
            _totalAmount,
            // forge-lint: disable-next-line(unsafe-typecast) commitmentCount <= maxBatchSize (uint32)
            uint16(commitmentCount),
            commitmentsHash,
            _commitments,
            _ciphertexts
        );
    }

    /// @inheritdoc IPrivacyBoost
    function cancelDeposit(uint256 _depositRequestId) external nonReentrant {
        PendingDeposit storage pd = pendingDeposits[_depositRequestId];

        if (pd.depositor != msg.sender) revert NotDepositor();
        if (processedDeposits[_depositRequestId]) revert DepositAlreadyProcessed();
        if (block.number < pd.requestBlock + cancelDelay) revert CancelTooEarly();

        (, address tokenAddress,) = tokenRegistry.tokenOf(pd.tokenId);
        IERC20(tokenAddress).safeTransfer(msg.sender, pd.totalAmount);
        delete pendingDeposits[_depositRequestId];

        emit DepositCancelled(_depositRequestId);
    }

    /// @inheritdoc IPrivacyBoost
    function submitDepositEpoch(
        EpochTreeState calldata treeState,
        uint32 nTotalCommitments,
        Output[] calldata outputs,
        DepositEntry[] calldata deposits,
        uint256[8] calldata proof
    ) external nonReentrant onlyRelay {
        uint32 maxSlots = uint32(outputs.length);
        uint32 nRequests = uint32(deposits.length);

        if (maxSlots == 0 || maxSlots > maxBatchSize) revert InvalidEpochConfig();
        if (nRequests == 0 || nRequests > maxSlots) revert InvalidEpochConfig();
        if (nTotalCommitments == 0 || nTotalCommitments > maxSlots) revert InvalidEpochConfig();

        // Tree state must match on-chain state exactly
        if (treeState.activeTreeNumber != currentTreeNumber) revert InvalidEpochState();
        if (treeState.countOld != treeCount[treeState.activeTreeNumber]) revert InvalidEpochState();

        // Validate sparse roots (deposit requires unique tree numbers for selectByTreeNumber safety)
        uint256 activeRoot = _validateKnownRoots(treeState.usedRoots, treeState.activeTreeNumber, false);
        // Epochs require the exact current root (append-only tree guarantees state consistency)
        if (activeRoot != treeRoot[treeState.activeTreeNumber]) revert InvalidEpochState();
        _validateTreeCapacity(treeState.countOld, treeState.countNew, nTotalCommitments, treeState.rollover);

        uint256[] memory depositRequestIds = new uint256[](maxSlots);
        uint256[] memory totalAmounts = new uint256[](maxSlots);
        uint256[] memory commitmentCounts = new uint256[](maxSlots);
        uint256[] memory commitmentsOut = new uint256[](maxSlots);
        uint256 commitmentCursor = 0;

        for (uint256 r = 0; r < nRequests; ++r) {
            uint256 reqId = deposits[r].depositRequestId;
            PendingDeposit storage pd = pendingDeposits[reqId];

            if (pd.depositor == address(0)) revert InvalidDeposit();
            if (processedDeposits[reqId]) revert DepositAlreadyProcessed();
            processedDeposits[reqId] = true;

            depositRequestIds[r] = reqId;
            totalAmounts[r] = pd.totalAmount;
            commitmentCounts[r] = pd.commitmentCount;

            uint256 computedHash = 0;
            uint256 endCursor = commitmentCursor + pd.commitmentCount;
            if (endCursor > nTotalCommitments) revert InvalidArrayLengths();
            for (; commitmentCursor < endCursor; ++commitmentCursor) {
                uint256 commitment = outputs[commitmentCursor].commitment;
                commitmentsOut[commitmentCursor] = commitment;
                computedHash = LibDigest.computeCommitmentsHashStep(computedHash, commitment);
            }

            if (computedHash != pd.commitmentsHash) revert InvalidDeposit();
        }

        if (commitmentCursor != nTotalCommitments) revert InvalidArrayLengths();

        uint256[] memory publicInputs = LibPublicInputs.buildDepositInputs(
            block.chainid,
            address(this),
            treeState,
            nRequests,
            nTotalCommitments,
            depositRequestIds,
            totalAmounts,
            commitmentCounts,
            commitmentsOut
        );

        depositVerifier.verifyDeposit(maxSlots, proof, publicInputs);

        _updateTreeState(treeState.activeTreeNumber, treeState.rootNew, treeState.countNew, treeState.rollover);

        emit DepositEpochSubmitted(
            currentTreeNumber, treeState.rootNew, treeState.rollover ? 0 : treeState.countOld, treeState.countNew
        );
    }

    /// @inheritdoc IPrivacyBoost
    function requestForcedWithdrawal(
        TreeRootPair[] calldata knownRoots,
        AuthSnapshotState calldata authState,
        uint256 spenderAccountId,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        Withdrawal calldata withdrawal,
        uint256[8] calldata proof
    ) external nonReentrant {
        uint256 inputLen = nullifiers.length;
        if (inputLen == 0 || inputLen != inputCommitments.length) revert InvalidArrayLengths();
        if (inputLen > maxForcedInputs) revert InvalidEpochConfig();
        if (inputLen > type(uint8).max) revert InvalidArrayLengths();
        if (withdrawal.to == address(0)) revert InvalidWithdrawal();

        // Validate tokenId at request time to prevent locking commitments for unexecutable requests.
        (uint8 tokenType, address tokenAddress,) = tokenRegistry.tokenOf(withdrawal.tokenId);
        if (tokenAddress == address(0)) revert InvalidWithdrawal();
        if (tokenType != TOKEN_TYPE_ERC20) revert TokenNotSupported(tokenType);

        uint256 treeNum = currentTreeNumber;

        // Validate sparse roots and get active tree root (forced withdrawal requires unique tree numbers)
        uint256 activeRoot = _validateKnownRoots(knownRoots, treeNum, false);
        // Forced withdrawal is permissionless, so it must not be able to create new auth snapshots.
        // Callers can reference an existing snapshot round (e.g., latestSnapshotRound) to avoid races.
        _validateAuthKnownRootsSparse(authState.usedAuthRoots, authState.authSnapshotRound, false);

        // Block double-spend and double-request (commitment collision is cryptographically negligible)
        for (uint256 i = 0; i < inputLen; ++i) {
            if (nullifiers[i] == 0) revert InvalidNullifierSet();
            if (nullifierSpent[nullifiers[i]]) revert InvalidNullifierSet();
            if (commitmentToRequestKey[inputCommitments[i]] != 0) revert ForcedWithdrawalAlreadyRequested();

            // Check for duplicates within the same request (O(n²) but n <= maxForcedInputs which is small)
            for (uint256 j = 0; j < i; ++j) {
                if (nullifiers[j] == nullifiers[i]) revert DuplicateNullifier();
                if (inputCommitments[j] == inputCommitments[i]) revert DuplicateInputCommitment();
            }
        }

        bytes32 digest =
            LibDigest.computeForcedWithdrawalDigest(block.chainid, address(this), activeRoot, nullifiers, withdrawal);

        uint256 maxInputs = uint256(maxForcedInputs);
        uint256[] memory nullifiersPadded = new uint256[](maxInputs);
        uint256[] memory inputCommitmentsPadded = new uint256[](maxInputs);
        for (uint256 i = 0; i < inputLen; ++i) {
            nullifiersPadded[i] = nullifiers[i];
            inputCommitmentsPadded[i] = inputCommitments[i];
        }

        uint256[] memory publicInputs = LibPublicInputs.buildForcedWithdrawalInputs(
            knownRoots,
            authState,
            inputLen,
            spenderAccountId,
            nullifiersPadded,
            inputCommitmentsPadded,
            digest,
            withdrawal.to,
            withdrawal.tokenId,
            withdrawal.amount
        );

        forcedVerifier.verifyForcedWithdraw(maxForcedInputs, proof, publicInputs);

        bytes32 nullifiersHash = keccak256(abi.encodePacked(nullifiers));
        bytes32 commitmentsHash = keccak256(abi.encodePacked(inputCommitments));
        uint256 requestKey = LibDigest.computeRequestKey(msg.sender, commitmentsHash);

        // Capture fee rate at request time for predictable execution
        // forge-lint: disable-next-line(unsafe-typecast) inputLen checked above (inputLen <= uint8.max)
        forcedWithdrawalRequests[requestKey] = ForcedWithdrawalRequest({
            requestBlock: uint64(block.number),
            requester: msg.sender,
            withdrawalTo: withdrawal.to,
            tokenId: withdrawal.tokenId,
            amount: withdrawal.amount,
            withdrawFeeBps: withdrawFeeBps,
            inputCount: uint8(inputLen),
            spenderAccountId: spenderAccountId,
            nullifiersHash: nullifiersHash,
            commitmentsHash: commitmentsHash
        });

        for (uint256 i = 0; i < inputLen; ++i) {
            commitmentToRequestKey[inputCommitments[i]] = requestKey;
        }

        emit ForcedWithdrawalRequested(
            msg.sender, withdrawal.to, withdrawal.tokenId, withdrawal.amount, nullifiers, inputCommitments
        );
    }

    /// @inheritdoc IPrivacyBoost
    function executeForcedWithdrawal(uint256[] calldata nullifiers, uint256[] calldata inputCommitments)
        external
        nonReentrant
    {
        (ForcedWithdrawalRequest storage request, uint256 requestKey, uint256 inputLen) =
            _validateForcedWithdrawalExecution(nullifiers, inputCommitments, true);

        for (uint256 i = 0; i < inputLen; ++i) {
            if (nullifierSpent[nullifiers[i]]) revert InvalidNullifierSet();
        }

        address withdrawalTo = request.withdrawalTo;
        uint16 tokenId = request.tokenId;
        uint96 grossAmount = request.amount;
        uint16 requestFeeBps = request.withdrawFeeBps;

        // forge-lint: disable-next-line(unsafe-typecast) fee < 10% of uint96 grossAmount
        uint96 feeAmount = uint96((uint256(grossAmount) * requestFeeBps) / BASIS_POINTS);
        uint96 netAmount = grossAmount - feeAmount;

        for (uint256 i = 0; i < inputLen; ++i) {
            nullifierSpent[nullifiers[i]] = true;
        }

        _clearForcedWithdrawalRequest(inputCommitments, requestKey, inputLen);
        _transferToken(tokenId, withdrawalTo, netAmount);

        if (feeAmount > 0 && treasury != address(0)) {
            _transferToken(tokenId, treasury, feeAmount);
        }

        emit ForcedWithdrawalExecuted(withdrawalTo, tokenId, netAmount, nullifiers, inputCommitments);
    }

    /// @inheritdoc IPrivacyBoost
    function cancelForcedWithdrawal(uint256[] calldata nullifiers, uint256[] calldata inputCommitments)
        external
        nonReentrant
    {
        (, uint256 requestKey, uint256 inputLen) =
            _validateForcedWithdrawalCancellation(nullifiers, inputCommitments, false, true);

        _clearForcedWithdrawalRequest(inputCommitments, requestKey, inputLen);

        emit ForcedWithdrawalCancelled(nullifiers, inputCommitments);
    }

    /// @inheritdoc IPrivacyBoost
    function isKnownTreeRoot(uint256 treeNum, uint256 root_) public view returns (bool) {
        if (root_ == 0) return false;

        // O(1) fast path: current root matches for any tree
        if (treeRoot[treeNum] == root_) return true;

        // Finalized trees: only the final root is valid (checked above)
        if (treeNum < currentTreeNumber) return false;

        // Current tree: scan ring buffer for historical roots
        uint256 idx = treeRootHistoryCursor[treeNum];
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; ++i) {
            if (treeRootHistory[treeNum][idx] == root_) return true;
            unchecked {
                idx = (idx + ROOT_HISTORY_SIZE - 1) % ROOT_HISTORY_SIZE;
            }
        }
        return false;
    }

    /// @dev Set fee rates with validation
    function _setFees(uint16 withdrawFeeBps_) internal {
        if (withdrawFeeBps_ > MAX_FEE_BPS) {
            revert FeeExceedsMaximum();
        }
        if (withdrawFeeBps_ > 0 && treasury == address(0)) {
            revert TreasuryNotSet();
        }
        withdrawFeeBps = withdrawFeeBps_;
        emit FeesUpdated(withdrawFeeBps_);
    }

    function _zeroRoot() internal view returns (uint256) {
        return LibZeroHashes.get()[merkleDepth];
    }

    function _pushTreeRoot(uint256 treeNum, uint256 rootNew) internal {
        uint256 next = (treeRootHistoryCursor[treeNum] + 1) % ROOT_HISTORY_SIZE;
        treeRootHistory[treeNum][next] = rootNew;
        treeRootHistoryCursor[treeNum] = next;
    }

    function _validateForcedWithdrawalCancellation(
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        bool checkMaxInputs,
        bool allowOwnerCancel
    ) internal view returns (ForcedWithdrawalRequest storage request, uint256 requestKey, uint256 inputLen) {
        inputLen = inputCommitments.length;
        if (inputLen == 0) revert InvalidArrayLengths();
        if (nullifiers.length != inputLen) revert InvalidArrayLengths();
        if (checkMaxInputs && inputLen > maxForcedInputs) revert InvalidEpochConfig();

        bytes32 commitmentsHash = keccak256(abi.encodePacked(inputCommitments));

        // Try to find request: first as requester, then via commitment lookup for owner cancel
        requestKey = LibDigest.computeRequestKey(msg.sender, commitmentsHash);
        request = forcedWithdrawalRequests[requestKey];

        bool isRequester = (request.requestBlock != 0 && request.requester == msg.sender);

        if (!isRequester) {
            // If not found as requester, try commitment lookup for owner cancel
            if (!allowOwnerCancel) revert NotRequester();

            requestKey = commitmentToRequestKey[inputCommitments[0]];
            if (requestKey == 0) revert ForcedWithdrawalNotRequested();
            request = forcedWithdrawalRequests[requestKey];
            if (request.requestBlock == 0) revert ForcedWithdrawalNotRequested();

            // Verify caller is the account owner
            address accountOwner = authRegistry.ownerOf(request.spenderAccountId);
            if (msg.sender != accountOwner) revert NotRequesterOrOwner();
        }

        if (block.number < request.requestBlock + forcedWithdrawalDelay) revert ForcedWithdrawalTooEarly();
        if (inputLen != request.inputCount) revert ForcedWithdrawalMismatch();

        bytes32 nullifiersHash = keccak256(abi.encodePacked(nullifiers));
        if (nullifiersHash != request.nullifiersHash) revert ForcedWithdrawalMismatch();
        if (commitmentsHash != request.commitmentsHash) revert ForcedWithdrawalMismatch();
    }

    function _validateForcedWithdrawalExecution(
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        bool checkMaxInputs
    ) internal view returns (ForcedWithdrawalRequest storage request, uint256 requestKey, uint256 inputLen) {
        inputLen = inputCommitments.length;
        if (inputLen == 0) revert InvalidArrayLengths();
        if (nullifiers.length != inputLen) revert InvalidArrayLengths();
        if (checkMaxInputs && inputLen > maxForcedInputs) revert InvalidEpochConfig();

        requestKey = commitmentToRequestKey[inputCommitments[0]];
        if (requestKey == 0) revert ForcedWithdrawalNotRequested();
        request = forcedWithdrawalRequests[requestKey];
        if (request.requestBlock == 0) revert ForcedWithdrawalNotRequested();

        if (block.number < request.requestBlock + forcedWithdrawalDelay) revert ForcedWithdrawalTooEarly();
        if (inputLen != request.inputCount) revert ForcedWithdrawalMismatch();

        bytes32 nullifiersHash = keccak256(abi.encodePacked(nullifiers));
        if (nullifiersHash != request.nullifiersHash) revert ForcedWithdrawalMismatch();

        bytes32 commitmentsHash = keccak256(abi.encodePacked(inputCommitments));
        if (commitmentsHash != request.commitmentsHash) revert ForcedWithdrawalMismatch();
    }

    function _clearForcedWithdrawalRequest(uint256[] calldata inputCommitments, uint256 requestKey, uint256 inputLen)
        internal
    {
        for (uint256 i = 0; i < inputLen; ++i) {
            delete commitmentToRequestKey[inputCommitments[i]];
        }
        delete forcedWithdrawalRequests[requestKey];
    }

    function _transferToken(uint16 tokenId, address to, uint96 amount) internal {
        (uint8 tokenType, address tokenAddress,) = tokenRegistry.tokenOf(tokenId);
        if (tokenAddress == address(0)) revert InvalidWithdrawal();
        if (tokenType != TOKEN_TYPE_ERC20) revert TokenNotSupported(tokenType);
        IERC20(tokenAddress).safeTransfer(to, amount);
    }

    function _processWithdrawals(Withdrawal[] calldata withdrawals) internal {
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            Withdrawal calldata w = withdrawals[i];
            _transferToken(w.tokenId, w.to, w.amount);
        }
    }

    function _validateTreeCapacity(uint32 countOld, uint32 countNew, uint256 totalOutputs, bool rollover)
        internal
        view
    {
        uint256 maxLeaves = uint256(1) << merkleDepth;
        uint256 expectedCountNew = rollover ? totalOutputs : uint256(countOld) + totalOutputs;
        if (rollover && countOld != maxLeaves) revert InvalidEpochState();
        if (!rollover && uint256(countOld) >= maxLeaves) revert InvalidEpochState();
        if (countNew != expectedCountNew || expectedCountNew > maxLeaves) revert InvalidEpochState();
    }

    function _updateTreeState(uint256 activeTreeNumber, uint256 rootNew, uint32 countNew, bool rollover) internal {
        if (rollover) {
            uint256 newTreeNumber = currentTreeNumber + 1;
            if (newTreeNumber > MAX_NOTE_TREE_NUMBER) revert InvalidEpochState();
            currentTreeNumber = newTreeNumber;
            treeRoot[newTreeNumber] = rootNew;
            treeCount[newTreeNumber] = countNew;
            _pushTreeRoot(newTreeNumber, rootNew);

            emit TreeAdvanced(activeTreeNumber, newTreeNumber);
        } else {
            treeRoot[activeTreeNumber] = rootNew;
            treeCount[activeTreeNumber] = countNew;
            _pushTreeRoot(activeTreeNumber, rootNew);
        }
    }

    function _validateWithdrawalSlots(uint32[] calldata withdrawalSlots, uint256 withdrawalsLen, uint32 nTransfers)
        internal
        pure
    {
        if (withdrawalSlots.length != withdrawalsLen) revert InvalidArrayLengths();
        uint32 prevSlot = 0;
        for (uint256 i = 0; i < withdrawalSlots.length; ++i) {
            uint32 slot = withdrawalSlots[i];
            if (slot >= nTransfers) revert InvalidWithdrawal();
            if (i > 0 && slot <= prevSlot) revert WithdrawalSlotsNotStrictAscending(i, prevSlot, slot);
            prevSlot = slot;
        }
    }

    function _computeTransferDigests(
        uint32[] calldata inputsPerTransfer,
        uint32[] calldata outputsPerTransfer,
        uint256[][] calldata nullifiers,
        Transfer[] calldata transfers,
        Withdrawal[] calldata withdrawals,
        uint32[] calldata withdrawalSlots,
        TreeRootPair[] calldata usedRoots,
        uint256[] calldata digestRootIndices,
        uint256 transferCount,
        uint32 nTransfers,
        uint32 circuitMaxOutputs
    )
        internal
        view
        returns (
            uint256[][] memory commitmentsOut,
            uint256[] memory approveDigestHi,
            uint256[] memory approveDigestLo,
            uint256 digestRootMask
        )
    {
        approveDigestHi = new uint256[](transferCount);
        approveDigestLo = new uint256[](transferCount);
        commitmentsOut = new uint256[][](transferCount);
        uint256 withdrawalsLen = withdrawals.length;
        if (withdrawalSlots.length != withdrawalsLen) revert InvalidArrayLengths();
        uint256 withdrawalCursor = 0;
        digestRootMask = 0;

        for (uint256 t = 0; t < transferCount; ++t) {
            commitmentsOut[t] = new uint256[](circuitMaxOutputs);

            // Inactive slots: arrays stay zero-initialized, matching prover's (0, 0) padding
            if (t >= nTransfers) {
                continue;
            }

            // Resolve per-transfer digest root from packed 4-bit indices
            uint256 word = digestRootIndices[t / 64];
            uint256 slotIdx = (word >> ((t % 64) * 4)) & 0xF;
            if (slotIdx >= usedRoots.length) revert InvalidBatchConfig();
            uint256 digestRoot = usedRoots[slotIdx].root;
            digestRootMask |= (uint256(1) << slotIdx);

            // Extract commitments for public inputs
            for (uint256 j = 0; j < circuitMaxOutputs; ++j) {
                commitmentsOut[t][j] = transfers[t].outputs[j].commitment;
            }

            // Build trimmed arrays for digest (actual counts, not circuit-padded)
            uint32 nInputs = inputsPerTransfer[t];
            uint32 nOutputs = outputsPerTransfer[t];

            uint256[] memory nullifiersForDigest = new uint256[](nInputs);
            Output[] memory outputsForDigest = new Output[](nOutputs);

            for (uint256 i = 0; i < nInputs; ++i) {
                nullifiersForDigest[i] = nullifiers[t][i];
            }
            for (uint256 j = 0; j < nOutputs; ++j) {
                outputsForDigest[j] = transfers[t].outputs[j];
            }

            // Compute approval digest (withdrawal or transfer)
            if (withdrawalCursor < withdrawalsLen && withdrawalSlots[withdrawalCursor] == uint32(t)) {
                Withdrawal calldata w = withdrawals[withdrawalCursor];
                if (w.amount == 0) revert InvalidWithdrawal();

                uint256 expectedCommitment = LibDigest.computeWithdrawalCommitment(w.to, w.tokenId, w.amount);
                if (transfers[t].outputs[0].commitment != expectedCommitment) revert InvalidWithdrawal();

                (approveDigestHi[t], approveDigestLo[t]) = LibDigest.computeWithdrawalDigest(
                    block.chainid,
                    address(this),
                    digestRoot,
                    nullifiersForDigest,
                    outputsForDigest,
                    w,
                    transfers[t].viewingKey,
                    transfers[t].teeWrapKey
                );
                unchecked {
                    ++withdrawalCursor;
                }
            } else {
                (approveDigestHi[t], approveDigestLo[t]) = LibDigest.computeTransferDigest(
                    block.chainid,
                    address(this),
                    digestRoot,
                    nullifiersForDigest,
                    outputsForDigest,
                    transfers[t].viewingKey,
                    transfers[t].teeWrapKey
                );
            }
        }

        if (withdrawalCursor != withdrawalsLen) revert InvalidArrayLengths();
    }

    /// @dev Validates the zero/non-zero invariant for nullifier and commitment slots.
    /// Active slots (index < per-transfer count) must be non-zero; inactive slots must be zero.
    /// This binds per-transfer counts between the circuit and contract, preventing count mismatch attacks.
    function _validateSlotPadding(
        uint256[][] calldata nullifiers,
        uint256[][] memory commitmentsOut,
        uint32[] calldata inputsPerTransfer,
        uint32[] calldata outputsPerTransfer,
        uint32 nTransfers,
        uint32 transferCount,
        uint32 circuitMaxInputs,
        uint32 circuitMaxOutputs
    ) internal pure {
        for (uint256 t = 0; t < transferCount; ++t) {
            uint32 nIn = t < nTransfers ? inputsPerTransfer[t] : 0;
            uint32 nOut = t < nTransfers ? outputsPerTransfer[t] : 0;

            for (uint256 i = 0; i < circuitMaxInputs; ++i) {
                if ((nullifiers[t][i] != 0) != (i < nIn)) revert InvalidSlotPadding();
            }
            for (uint256 j = 0; j < circuitMaxOutputs; ++j) {
                if ((commitmentsOut[t][j] != 0) != (j < nOut)) revert InvalidSlotPadding();
            }
        }
    }

    /// @dev Spend nullifiers from per-transfer 2D array
    function _spendNullifiers(uint256[][] calldata nullifiers, uint32[] calldata inputsPerTransfer, uint32 nTransfers)
        internal
    {
        for (uint256 t = 0; t < nTransfers; ++t) {
            uint32 nInputs = inputsPerTransfer[t];
            for (uint256 i = 0; i < nInputs; ++i) {
                uint256 nullifier = nullifiers[t][i];
                if (nullifier == 0) revert InvalidNullifierSet();
                if (nullifierSpent[nullifier]) revert InvalidNullifierSet();
                nullifierSpent[nullifier] = true;
            }
        }
    }

    function _buildFeeCommitments(Transfer calldata feeTransfer, uint32 feeCount)
        internal
        pure
        returns (uint256[] memory feeCommitmentsOut)
    {
        feeCommitmentsOut = new uint256[](feeCount);
        for (uint256 i = 0; i < feeCount; ++i) {
            feeCommitmentsOut[i] = feeTransfer.outputs[i].commitment;
        }
    }

    /// @dev Validate sparse known roots. Returns the active tree's root.
    /// @param sparseRoots Sparse array with (treeNumber, root) pairs
    /// @param activeTreeNumber Must be included
    /// @return activeRoot The root provided for the active tree
    function _validateKnownRoots(
        TreeRootPair[] calldata sparseRoots,
        uint256 activeTreeNumber,
        bool allowDuplicateTreeNumbers
    ) internal view returns (uint256 activeRoot) {
        uint256 len = sparseRoots.length;
        if (len == 0 || len > MAX_NOTE_ROOTS_PER_PROOF) revert InvalidBatchConfig();

        bool foundActive = false;
        for (uint256 i = 0; i < len; ++i) {
            uint256 treeNum = sparseRoots[i].treeNumber;
            uint256 root = sparseRoots[i].root;

            // Enforce uniqueness rules for sparse roots:
            // - Deposit/forced withdrawal require unique tree numbers (selectByTreeNumber safety).
            // - Epoch allows duplicate tree numbers because each transfer independently selects its digest root via
            //   digestRootIndices; input spending uses findPairMatch (OR-based, safe with duplicates).
            //   Even in epoch, exact duplicate (treeNumber, root) pairs are rejected (no functional value, reduces malleability).
            if (allowDuplicateTreeNumbers) {
                for (uint256 j = 0; j < i; ++j) {
                    if (sparseRoots[j].treeNumber == treeNum && sparseRoots[j].root == root) {
                        revert DuplicateTreeRootPair();
                    }
                }
            } else {
                for (uint256 j = 0; j < i; ++j) {
                    if (sparseRoots[j].treeNumber == treeNum) revert DuplicateTreeNumber();
                }
            }

            // Validate root is known for this tree
            if (!isKnownTreeRoot(treeNum, root)) revert RootNotKnown();

            // Track active tree
            if (treeNum == activeTreeNumber) {
                activeRoot = root;
                foundActive = true;
            }
        }

        if (!foundActive) revert InvalidEpochState();
    }

    /// @dev Lazily snapshot a single auth tree for a round
    function _snapshotAuthTreeIfNeeded(uint256 targetRound, uint256 treeNum) internal {
        if (authSnapshots[targetRound][treeNum] == 0) {
            uint256 currentRound = _currentAuthSnapshotRoundSync();
            if (targetRound != currentRound) revert InvalidAuthSnapshotRound();

            // Verify tree exists
            uint256 currentAuthTree = authRegistry.currentAuthTreeNumber();
            if (treeNum > currentAuthTree) revert InvalidAuthTreeNumber();

            // Take snapshot
            authSnapshots[targetRound][treeNum] = authRegistry.authTreeRoot(treeNum);

            // Update tracking
            if (targetRound > latestSnapshotRound) {
                latestSnapshotRound = targetRound;
            }

            emit AuthTreeSnapshotted(targetRound, treeNum, authSnapshots[targetRound][treeNum]);
        }
    }

    /// @notice Snapshot auth tree roots for the current round
    /// @dev Only callable by allowed relays.
    ///      This provides a deterministic, relay-controlled way to establish snapshots
    ///      ahead of permissionless flows (e.g., forced withdrawals).
    /// @param treeNums Auth tree numbers to snapshot
    function snapshotAuthTrees(uint256[] calldata treeNums) external onlyRelay {
        uint256 len = treeNums.length;
        if (len == 0 || len > MAX_AUTH_ROOTS_PER_PROOF) revert InvalidBatchConfig();
        uint256 targetRound = _currentAuthSnapshotRoundSync();
        for (uint256 i = 0; i < len; ++i) {
            _snapshotAuthTreeIfNeeded(targetRound, treeNums[i]);
        }
    }

    /// @dev Validate auth roots and (optionally) perform lazy snapshotting as needed
    function _validateAuthKnownRootsSparse(
        TreeRootPair[] calldata sparseAuthRoots,
        uint256 targetRound,
        bool allowLazySnapshot
    ) internal {
        uint256 len = sparseAuthRoots.length;
        if (len == 0 || len > MAX_AUTH_ROOTS_PER_PROOF) revert InvalidBatchConfig();

        uint256 currentRound = _currentAuthSnapshotRoundSync();
        bool isCurrentRound = (targetRound == currentRound);

        // Validate round window:
        // 1. Current round (lazy snapshot)
        // 2. Current round - 1 (grace period, must be already snapshotted)
        // 3. latestSnapshotRound (extended inactivity: no new activity since then, only if snapshots exist)
        // 4. latestSnapshotRound - 1 (grace period from latestSnapshotRound)
        bool isValidRound = isCurrentRound || (targetRound + 1 == currentRound)
            || (latestSnapshotRound > 0 && targetRound == latestSnapshotRound)
            || (latestSnapshotRound > 0 && targetRound + 1 == latestSnapshotRound);

        if (!isValidRound) {
            revert InvalidAuthSnapshotRound();
        }

        for (uint256 i = 0; i < len; ++i) {
            uint256 treeNum = sparseAuthRoots[i].treeNumber;
            uint256 root = sparseAuthRoots[i].root;

            // Enforce uniqueness of treeNumber in sparse auth roots.
            // Duplicates are ambiguous and can desync circuit vs on-chain interpretation.
            for (uint256 j = 0; j < i; ++j) {
                if (sparseAuthRoots[j].treeNumber == treeNum) revert DuplicateTreeNumber();
            }

            if (root == 0) revert RootNotKnown();

            if (isCurrentRound) {
                if (allowLazySnapshot) {
                    // Current round: lazy snapshot
                    _snapshotAuthTreeIfNeeded(targetRound, treeNum);
                } else {
                    // Current round: must already be snapshotted
                    if (authSnapshots[targetRound][treeNum] == 0) {
                        revert AuthTreeNotSnapshotted();
                    }
                }
            } else {
                // Previous round or extended inactivity: must already be snapshotted
                if (authSnapshots[targetRound][treeNum] == 0) {
                    revert AuthTreeNotSnapshotted();
                }
            }

            // Validate against snapshot
            if (root != authSnapshots[targetRound][treeNum]) {
                revert RootNotKnown();
            }
        }
    }

    uint256[44] private __gap;
}
