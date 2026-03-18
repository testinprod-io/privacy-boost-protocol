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
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {
    DOMAIN_ACCOUNTID,
    DOMAIN_REG_LEAF,
    DOMAIN_REG_NODE,
    ROOT_HISTORY_SIZE,
    AUTH_ZERO_ROOT
} from "src/interfaces/Constants.sol";
import "src/interfaces/Constants.sol" as ContractConstants;
import {LibAuthZeroHashes} from "src/lib/LibAuthZeroHashes.sol";
import {EcdsaSig, AuthKeyInfo, AccountInfo, AuthTreeState} from "src/interfaces/IStructs.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";
import {LibBabyJubJub} from "src/lib/LibBabyJubJub.sol";

/// @title AuthRegistry
/// @notice Poseidon Merkle registry for approval keys with multi-tree support
contract AuthRegistry is IAuthRegistry, Ownable2StepUpgradeable {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("PB:AuthRegistry:vNext");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(uint256 accountId,uint256 authPkX,uint256 authPkY,uint64 expiry,uint256 nonce)");
    bytes32 private constant ROTATE_TYPEHASH = keccak256(
        "Rotate(uint256 accountId,uint256 oldAuthPkX,uint256 authPkX,uint256 authPkY,uint64 expiry,uint256 nonce)"
    );
    bytes32 private constant REVOKE_TYPEHASH =
        keccak256("Revoke(uint256 accountId,uint256 authPkX,uint64 expiry,uint256 nonce)");

    /// @notice Maximum number of auth trees supported (tree numbers are 0..MAX_AUTH_TREE_NUMBER-1)
    uint16 public constant MAX_AUTH_TREE_NUMBER = ContractConstants.MAX_AUTH_TREE_NUMBER;

    /// @notice Size of the root history ring buffer per tree
    uint256 public constant AUTH_ROOT_HISTORY_SIZE = ROOT_HISTORY_SIZE;

    /// @notice The depth of the auth Merkle tree
    uint8 public immutable authTreeDepth;

    /// @dev Per-tree Merkle state (packed: root + cursor + leafCount)
    uint256 public currentAuthTreeNumber;
    mapping(uint256 treeNum => AuthTreeState) internal _authTreeState;

    /// @notice Historical roots for each auth tree (by tree number and history index)
    mapping(uint256 treeNum => mapping(uint256 idx => uint256 root)) public authTreeRootHistory;

    /// @dev Account ownership and replay protection (packed: owner + nonce)
    mapping(uint256 accountId => AccountInfo) internal _accountInfo;
    mapping(uint256 treeNum => mapping(uint256 level => mapping(uint256 idx => uint256 value))) internal nodes;

    /// @notice True for allowed relay addresses
    mapping(address relay => bool allowed) public allowedRelays;

    /// @notice Operator address for operational functions
    address public operator;

    /// @dev Multi-device support: authKeyId = keccak256(accountId, authPkX)
    mapping(bytes32 authKeyId => AuthKeyInfo) internal _authKeyInfo;
    mapping(uint256 accountId => bytes32[] authKeyIds) internal _authKeyList;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(uint8 authTreeDepth_) {
        authTreeDepth = authTreeDepth_;
        _disableInitializers();
    }

    /// @inheritdoc IAuthRegistry
    function initialize(address initialOwner) external initializer {
        __Ownable2Step_init();
        _transferOwnership(initialOwner);
        uint256 zeroRoot = _zeroRoot();
        currentAuthTreeNumber = 0;
        _authTreeState[0].root = zeroRoot;
        authTreeRootHistory[0][0] = zeroRoot;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    /// @inheritdoc IAuthRegistry
    function setOperator(address operator_) external onlyOwner {
        if (operator_ == address(0)) revert InvalidOperatorAddress();
        address oldOperator = operator;
        operator = operator_;
        emit OperatorUpdated(oldOperator, operator_);
    }

    /// @inheritdoc IAuthRegistry
    function setAllowedRelays(address[] calldata relays, bool allowed) external onlyOperator {
        for (uint256 i = 0; i < relays.length; ++i) {
            if (relays[i] == address(0)) revert InvalidRelayAddress();
            allowedRelays[relays[i]] = allowed;
            emit RelayUpdated(relays[i], allowed);
        }
    }

    /// @inheritdoc IAuthRegistry
    function register(
        uint256 salt,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        address expectedOwner,
        EcdsaSig calldata sig
    ) external {
        uint256 accountId = computeAccountId(expectedOwner, salt);
        _registerAccount(accountId, authPkX, authPkY, expiry, expectedOwner, sig);
    }

    /// @inheritdoc IAuthRegistry
    function computeAccountId(address owner, uint256 salt) public pure returns (uint256) {
        return Poseidon2T4.hash3(DOMAIN_ACCOUNTID, uint256(uint160(owner)), salt);
    }

    function _registerAccount(
        uint256 accountId,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        address expectedOwner,
        EcdsaSig calldata sig
    ) internal {
        if (msg.sender != expectedOwner && !allowedRelays[msg.sender]) revert NotAuthorized();
        if (accountId == 0) revert InvalidAccountId();
        if (expiry != 0 && block.timestamp > expiry) revert SignatureExpired();
        if (!LibBabyJubJub.isValidPublicKey(authPkX, authPkY)) revert InvalidAuthPublicKey();

        bytes32 authKeyId = keccak256(abi.encode(accountId, authPkX));
        if (_authKeyInfo[authKeyId].listIndex != 0) revert AlreadyRegistered();

        AccountInfo storage account = _accountInfo[accountId];
        uint96 nonce = account.nonce;
        address recovered = _recoverRegister(accountId, authPkX, authPkY, expiry, nonce, sig);
        if (recovered != expectedOwner) revert InvalidSignature();

        address existingOwner = account.owner;
        if (existingOwner != address(0)) {
            if (existingOwner != expectedOwner) revert OwnerMismatch();
        } else {
            account.owner = expectedOwner;
        }

        uint256 treeNum = currentAuthTreeNumber;
        AuthTreeState storage treeState = _authTreeState[treeNum];
        uint32 idx = treeState.leafCount;

        if (idx >= (uint32(1) << authTreeDepth)) {
            treeNum = currentAuthTreeNumber + 1;
            if (treeNum > MAX_AUTH_TREE_NUMBER) revert RegistryFull();
            currentAuthTreeNumber = treeNum;
            treeState = _authTreeState[treeNum];
            uint256 zeroRoot = _zeroRoot();
            treeState.root = zeroRoot;
            authTreeRootHistory[treeNum][0] = zeroRoot;
            idx = 0;
        }

        account.nonce = nonce + 1;
        _authKeyInfo[authKeyId] = AuthKeyInfo({
            treeNumber: uint16(treeNum),
            treeIndex: idx,
            listIndex: uint32(_authKeyList[accountId].length) + 1, // 1-indexed
            revoked: false
        });
        _authKeyList[accountId].push(authKeyId);
        treeState.leafCount = idx + 1;

        uint256 leaf = computeLeaf(accountId, authPkX, authPkY, expiry);
        if (leaf == 0) revert InvalidLeaf();
        _updateLeaf(treeNum, idx, leaf);

        if (existingOwner == address(0)) {
            emit Registered(accountId, expectedOwner, treeNum, authPkX, authPkY, expiry);
        }
        emit AuthKeyAdded(accountId, authKeyId, treeNum, authPkX, authPkY);
    }

    /// @inheritdoc IAuthRegistry
    function rotate(
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 newAuthPkX,
        uint256 newAuthPkY,
        uint64 newExpiry,
        EcdsaSig calldata sig
    ) external {
        AccountInfo storage account = _accountInfo[accountId];
        address accountOwner = account.owner;
        if (accountOwner == address(0)) revert NotRegistered();
        if (msg.sender != accountOwner && !allowedRelays[msg.sender]) revert NotAuthorized();
        if (newExpiry != 0 && block.timestamp > newExpiry) revert SignatureExpired();

        bytes32 oldAuthKeyId = keccak256(abi.encode(accountId, oldAuthPkX));
        bytes32 newAuthKeyId = keccak256(abi.encode(accountId, newAuthPkX));

        AuthKeyInfo memory oldInfo = _authKeyInfo[oldAuthKeyId];
        if (oldInfo.listIndex == 0) revert AuthKeyNotFound();
        if (oldInfo.revoked) revert AuthKeyAlreadyRevoked();

        uint96 nonce = account.nonce;
        address signer = _recoverRotate(accountId, oldAuthPkX, newAuthPkX, newAuthPkY, newExpiry, nonce, sig);
        if (signer != accountOwner) revert InvalidSignature();
        if (!LibBabyJubJub.isValidPublicKey(newAuthPkX, newAuthPkY)) revert InvalidAuthPublicKey();

        account.nonce = nonce + 1;

        uint16 treeNum = oldInfo.treeNumber;
        uint32 idx = oldInfo.treeIndex;

        if (oldAuthPkX != newAuthPkX) {
            if (_authKeyInfo[newAuthKeyId].listIndex != 0) revert AlreadyRegistered();

            delete _authKeyInfo[oldAuthKeyId];
            _authKeyInfo[newAuthKeyId] =
                AuthKeyInfo({treeNumber: treeNum, treeIndex: idx, listIndex: oldInfo.listIndex, revoked: false});
            _authKeyList[accountId][oldInfo.listIndex - 1] = newAuthKeyId;
        }

        uint256 leaf = computeLeaf(accountId, newAuthPkX, newAuthPkY, newExpiry);
        if (leaf == 0) revert InvalidLeaf();
        _updateLeaf(treeNum, idx, leaf);

        emit AuthKeyRotated(accountId, newAuthKeyId, newAuthPkX, newAuthPkY, idx, newExpiry);
    }

    /// @inheritdoc IAuthRegistry
    function revoke(uint256 accountId, uint256 authPkX, uint64 expiry, EcdsaSig calldata sig) external {
        AccountInfo storage account = _accountInfo[accountId];
        address accountOwner = account.owner;
        if (accountOwner == address(0)) revert NotRegistered();
        if (msg.sender != accountOwner && !allowedRelays[msg.sender]) revert NotAuthorized();
        if (expiry != 0 && block.timestamp > expiry) revert SignatureExpired();

        bytes32 authKeyId = keccak256(abi.encode(accountId, authPkX));
        AuthKeyInfo storage info = _authKeyInfo[authKeyId];
        if (info.listIndex == 0) revert AuthKeyNotFound();
        if (info.revoked) revert AuthKeyAlreadyRevoked();

        uint96 nonce = account.nonce;
        address signer = _recoverRevoke(accountId, authPkX, expiry, nonce, sig);
        if (signer != accountOwner) revert InvalidSignature();

        account.nonce = nonce + 1;
        info.revoked = true;

        _updateLeaf(info.treeNumber, info.treeIndex, 0);

        emit AuthKeyRevoked(accountId, authKeyId, info.treeIndex);
    }

    /// @inheritdoc IAuthRegistry
    function computeLeaf(uint256 accountId, uint256 authPkX, uint256 authPkY, uint64 expiry)
        public
        pure
        returns (uint256)
    {
        return Poseidon2T4.hash5(DOMAIN_REG_LEAF, accountId, authPkX, authPkY, uint256(expiry));
    }

    function _updateLeaf(uint256 treeNum, uint256 index, uint256 leaf) internal {
        uint256[25] memory zeros = LibAuthZeroHashes.get();
        nodes[treeNum][0][index] = leaf;
        uint256 current = leaf;
        uint256 idx = index;
        for (uint256 level = 0; level < authTreeDepth; ++level) {
            uint256 siblingIndex = idx ^ 1;
            uint256 sibling = nodes[treeNum][level][siblingIndex];
            if (sibling == 0) {
                sibling = zeros[level];
            }
            uint256 left = (idx & 1 == 0) ? current : sibling;
            uint256 right = (idx & 1 == 0) ? sibling : current;
            current = Poseidon2T4.hash3(DOMAIN_REG_NODE, left, right);
            idx >>= 1;
            nodes[treeNum][level + 1][idx] = current;
        }
        AuthTreeState storage treeState = _authTreeState[treeNum];
        treeState.root = current;
        uint64 next = uint64((treeState.cursor + 1) % AUTH_ROOT_HISTORY_SIZE);
        authTreeRootHistory[treeNum][next] = current;
        treeState.cursor = next;
        emit RootUpdated(treeNum, current);
    }

    function _zeroRoot() internal view returns (uint256) {
        return LibAuthZeroHashes.get()[authTreeDepth];
    }

    /// @inheritdoc IAuthRegistry
    function getAllAuthTreeRoots() external view returns (uint256[] memory roots) {
        uint256 treeCount = currentAuthTreeNumber + 1;
        roots = new uint256[](treeCount);
        for (uint256 i = 0; i < treeCount; ++i) {
            roots[i] = _authTreeState[i].root;
        }
    }

    /// @inheritdoc IAuthRegistry
    function registryRoot() external view returns (uint256) {
        return _authTreeState[currentAuthTreeNumber].root;
    }

    /// @dev Compute EIP-712 domain separator for signature verification
    /// @return Domain separator hash
    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _recoverRegister(
        uint256 accountId,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        uint256 nonce,
        EcdsaSig calldata sig
    ) internal view returns (address) {
        bytes32 structHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, authPkX, authPkY, expiry, nonce));
        bytes32 digest = MessageHashUtils.toTypedDataHash(_domainSeparator(), structHash);
        return ECDSA.recover(digest, abi.encodePacked(sig.r, sig.s, sig.v));
    }

    function _recoverRotate(
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        uint256 nonce,
        EcdsaSig calldata sig
    ) internal view returns (address) {
        bytes32 structHash = keccak256(
            abi.encode(ROTATE_TYPEHASH, accountId, oldAuthPkX, authPkX, authPkY, expiry, nonce)
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(_domainSeparator(), structHash);
        return ECDSA.recover(digest, abi.encodePacked(sig.r, sig.s, sig.v));
    }

    function _recoverRevoke(uint256 accountId, uint256 authPkX, uint64 expiry, uint256 nonce, EcdsaSig calldata sig)
        internal
        view
        returns (address)
    {
        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, accountId, authPkX, expiry, nonce));
        bytes32 digest = MessageHashUtils.toTypedDataHash(_domainSeparator(), structHash);
        return ECDSA.recover(digest, abi.encodePacked(sig.r, sig.s, sig.v));
    }

    /// @inheritdoc IAuthRegistry
    function getAuthKeys(uint256 accountId) external view returns (bytes32[] memory) {
        return _authKeyList[accountId];
    }

    /// @inheritdoc IAuthRegistry
    function computeAuthKeyId(uint256 accountId, uint256 authPkX) external pure returns (bytes32) {
        return keccak256(abi.encode(accountId, authPkX));
    }

    /// @inheritdoc IAuthRegistry
    function getAuthKeyInfo(bytes32 authKeyId) external view returns (uint16 treeNum, uint32 index, bool revoked) {
        AuthKeyInfo memory info = _authKeyInfo[authKeyId];
        treeNum = info.treeNumber;
        index = info.treeIndex;
        revoked = info.revoked;
    }

    /// @inheritdoc IAuthRegistry
    function authKeyTreeOf(bytes32 authKeyId) external view returns (uint16) {
        return _authKeyInfo[authKeyId].treeNumber;
    }

    /// @inheritdoc IAuthRegistry
    function authKeyIndexOf(bytes32 authKeyId) external view returns (uint32) {
        return _authKeyInfo[authKeyId].treeIndex;
    }

    /// @inheritdoc IAuthRegistry
    function authKeyRevoked(bytes32 authKeyId) external view returns (bool) {
        return _authKeyInfo[authKeyId].revoked;
    }

    /// @inheritdoc IAuthRegistry
    function authTreeRoot(uint256 treeNum) external view returns (uint256) {
        return _authTreeState[treeNum].root;
    }

    /// @inheritdoc IAuthRegistry
    function authTreeCount(uint256 treeNum) external view returns (uint32) {
        return _authTreeState[treeNum].leafCount;
    }

    /// @inheritdoc IAuthRegistry
    function authTreeRootHistoryCursor(uint256 treeNum) external view returns (uint256) {
        return _authTreeState[treeNum].cursor;
    }

    /// @inheritdoc IAuthRegistry
    function ownerOf(uint256 accountId) external view returns (address) {
        return _accountInfo[accountId].owner;
    }

    /// @inheritdoc IAuthRegistry
    function nonces(uint256 accountId) external view returns (uint256) {
        return _accountInfo[accountId].nonce;
    }

    uint256[50] private __gap;
}
