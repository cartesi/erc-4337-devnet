// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.26;

import {HookConfig, ValidationFlags} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

import {LinkedListSet, SetValue} from "../libraries/LinkedListSetLib.sol";
import {ValidationLookupKey} from "../libraries/ValidationLocatorLib.sol";

// ERC-7201 derived storage slot.
// keccak256(abi.encode(uint256(keccak256("Alchemy.ModularAccount.Storage_V2")) - 1)) & ~bytes32(uint256(0xff))
bytes32 constant _ACCOUNT_STORAGE_SLOT = 0x596912a710dec01bac203cb0ed2c7e56a2ce6b2a68276967fff6dd57561bdd00;

/// @notice Represents data associated with a specific function selector.
struct ExecutionStorage {
    // The module that implements this execution function.
    // If this is a native function, the address should remain address(0).
    address module;
    // Whether or not the function needs runtime validation, or can be called without any validation. The function
    // can still be state changing if this flag is set to true.
    // Note that even if this is set to true, user op validation will still be required, otherwise any caller could
    // drain the account of native tokens by wasting gas.
    bool skipRuntimeValidation;
    // Whether or not a global validation function may be used to validate this function.
    bool allowGlobalValidation;
    // The execution hooks for this function selector.
    LinkedListSet executionHooks;
}

/// @notice Represents data associated with a specific validation function.
struct ValidationStorage {
    // The address of the validation module.
    address module;
    // ValidationFlags layout:
    // 0b00000___ // unused
    // 0b_____A__ // isGlobal
    // 0b______B_ // isSignatureValidation
    // 0b_______C // isUserOpValidation
    ValidationFlags validationFlags;
    // Length of the validation hooks for this validation function. The length is stored here, in the same storage
    // slot as the flags, to save an `sload` when putting the hooks into memory.
    uint8 validationHookCount;
    // Length of execution hooks for this validation function. The length is stored here, in the same storage slot
    // as the flags, to save an `sload` when putting the hooks into memory.
    uint8 executionHookCount;
    // The validation hooks for this validation function.
    LinkedListSet validationHooks;
    // Execution hooks to run with this validation function.
    LinkedListSet executionHooks;
    // The set of selectors that may be validated by this validation function.
    LinkedListSet selectors;
}

/// @custom:storage-location erc7201:Alchemy.ModularAccount.Storage_V2
struct AccountStorage {
    // AccountStorageInitializable variables.
    uint64 initialized;
    bool initializing;
    // Execution functions and their associated functions.
    mapping(bytes4 selector => ExecutionStorage) executionStorage;
    // Validation functions and their associated functions.
    mapping(ValidationLookupKey lookupKey => ValidationStorage) validationStorage;
    // Module-defined ERC-165 interfaces installed on the account.
    mapping(bytes4 => uint256) supportedIfaces;
}

function getAccountStorage() pure returns (AccountStorage storage _storage) {
    assembly ("memory-safe") {
        _storage.slot := _ACCOUNT_STORAGE_SLOT
    }
}

function toSetValue(HookConfig hookConfig) pure returns (SetValue) {
    return SetValue.wrap(bytes31(HookConfig.unwrap(hookConfig)));
}

function toSetValue(bytes4 selector) pure returns (SetValue) {
    return SetValue.wrap(bytes31(selector));
}
