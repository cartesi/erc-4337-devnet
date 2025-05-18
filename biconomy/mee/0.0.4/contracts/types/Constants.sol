// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

bytes3 constant SIG_TYPE_MEE_FLOW = 0x177eee;

bytes4 constant SIG_TYPE_SIMPLE = 0x177eee00;
bytes4 constant SIG_TYPE_ON_CHAIN = 0x177eee01;
bytes4 constant SIG_TYPE_ERC20_PERMIT = 0x177eee02;
// ...other sig types: ERC-7683, Permit2, etc

bytes4 constant EIP1271_SUCCESS = 0x1626ba7e;
bytes4 constant EIP1271_FAILED = 0xffffffff;

uint256 constant MODULE_TYPE_STATELESS_VALIDATOR = 7;
