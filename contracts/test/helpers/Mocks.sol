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

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockFeeOnTransferToken is ERC20 {
    uint256 public constant FEE_PERCENT = 1; // 1% fee

    constructor() ERC20("FeeToken", "FEE") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        uint256 fee = amount * FEE_PERCENT / 100;
        uint256 netAmount = amount - fee;
        _spendAllowance(from, msg.sender, amount);
        _transfer(from, to, netAmount);
        _burn(from, fee);
        return true;
    }
}

contract MockVerifier {
    function verifyEpoch(uint32, uint32, uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyDeposit(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyWithdraw(uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyForcedWithdraw(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }
}

contract MockAuthRegistry {
    function registryRoot() external pure returns (uint256) {
        return 1;
    }

    function currentAuthTreeNumber() external pure returns (uint256) {
        return 0;
    }

    function authTreeRoot(uint256) external pure returns (uint256) {
        return 1;
    }

    function getAllAuthTreeRoots() external pure returns (uint256[] memory roots) {
        roots = new uint256[](1);
        roots[0] = 1;
    }
}

contract MockAuthRegistryMultiTree {
    uint256 private _treeCount;
    mapping(uint256 => uint256) private _roots;

    constructor() {
        _treeCount = 0;
        _roots[0] = 1;
    }

    function registryRoot() external pure returns (uint256) {
        return 1;
    }

    function currentAuthTreeNumber() external view returns (uint256) {
        return _treeCount;
    }

    function authTreeRoot(uint256 treeNum) external view returns (uint256) {
        return _roots[treeNum];
    }

    function getAllAuthTreeRoots() external view returns (uint256[] memory roots) {
        roots = new uint256[](_treeCount + 1);
        for (uint256 i = 0; i <= _treeCount; i++) {
            roots[i] = _roots[i];
        }
    }

    function addAuthTree(uint256 root) external {
        _treeCount++;
        _roots[_treeCount] = root;
    }

    function setAuthTreeRoot(uint256 treeNum, uint256 root) external {
        _roots[treeNum] = root;
    }
}
