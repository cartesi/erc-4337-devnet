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

import {MAX_VALIDATION_ASSOC_HOOKS} from "@erc6900/reference-implementation/helpers/Constants.sol";
import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {
    HookConfig,
    IModularAccount,
    ModuleEntity,
    ValidationConfig,
    ValidationFlags
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";

import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";
import {MemManagementLib} from "../libraries/MemManagementLib.sol";
import {ModuleInstallCommonsLib} from "../libraries/ModuleInstallCommonsLib.sol";
import {ValidationLocatorLib} from "../libraries/ValidationLocatorLib.sol";
import {ValidationStorage, getAccountStorage, toSetValue} from "./AccountStorage.sol";

/// @title Module Manager Internals
/// @author Alchemy
/// @notice This abstract contract hosts the internal installation and uninstallation methods of execution and
/// validation functions. Methods here update the account storage.
abstract contract ModuleManagerInternals is IModularAccount {
    using LinkedListSetLib for LinkedListSet;
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;
    using HookConfigLib for HookConfig;

    error ArrayLengthMismatch();
    error PreValidationHookDuplicate();
    error ValidationEntityIdInUse();
    error ValidationAlreadySet(bytes4 selector, ModuleEntity validationFunction);
    error ValidationAssocHookLimitExceeded();

    function _setValidationFunction(
        ValidationStorage storage validationStorage,
        ValidationConfig validationConfig,
        bytes4[] calldata selectors
    ) internal {
        // To allow for flag updates and appending hooks and selectors, two cases should be considered:
        // - stored module address is zero - store the new validation module address
        // - stored module address already holds the address of the validation module being installed - update
        // flags and selectors.
        // If the stored module address does not match, revert, as the validation entity ID must be unique over the
        // account.

        address storedAddress = validationStorage.module;
        (address moduleAddress,, ValidationFlags validationFlags) = validationConfig.unpackUnderlying();

        if (storedAddress == address(0)) {
            validationStorage.module = moduleAddress;
        } else if (storedAddress != moduleAddress) {
            revert ValidationEntityIdInUse();
        }

        validationStorage.validationFlags = validationFlags;

        uint256 length = selectors.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = selectors[i];
            if (!validationStorage.selectors.tryAdd(toSetValue(selector))) {
                revert ValidationAlreadySet(selector, validationConfig.moduleEntity());
            }
        }
    }

    function _removeValidationFunction(ValidationStorage storage validationStorage) internal {
        validationStorage.module = address(0);
        validationStorage.validationFlags = ValidationFlags.wrap(0);
        validationStorage.validationHookCount = 0;
        validationStorage.executionHookCount = 0;
    }

    function _installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) internal {
        ValidationStorage storage _validationStorage =
            getAccountStorage().validationStorage[ValidationLocatorLib.configToLookupKey(validationConfig)];

        _setValidationFunction(_validationStorage, validationConfig, selectors);

        uint256 length = hooks.length;
        for (uint256 i = 0; i < length; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes25(hooks[i][:25]));
            bytes calldata hookData = hooks[i][25:];

            if (hookConfig.isValidationHook()) {
                // Increment the stored length of validation hooks, and revert if the limit is exceeded.

                // Safety:
                //     validationHookCount is uint8, so math operations here should never overflow
                unchecked {
                    if (uint256(_validationStorage.validationHookCount) + 1 > MAX_VALIDATION_ASSOC_HOOKS) {
                        revert ValidationAssocHookLimitExceeded();
                    }

                    ++_validationStorage.validationHookCount;
                }

                if (!_validationStorage.validationHooks.tryAdd(toSetValue(hookConfig))) {
                    revert PreValidationHookDuplicate();
                }

                ModuleInstallCommonsLib.onInstall(
                    hookConfig.module(), hookData, type(IValidationHookModule).interfaceId
                );
            } else {
                // Hook is an execution hook

                // Safety:
                //     validationHookCount is uint8, so math operations here should never overflow
                unchecked {
                    if (uint256(_validationStorage.executionHookCount) + 1 > MAX_VALIDATION_ASSOC_HOOKS) {
                        revert ValidationAssocHookLimitExceeded();
                    }

                    ++_validationStorage.executionHookCount;
                }

                ModuleInstallCommonsLib.addExecHooks(_validationStorage.executionHooks, hookConfig);
                ModuleInstallCommonsLib.onInstall(
                    hookConfig.module(), hookData, type(IExecutionHookModule).interfaceId
                );
            }
        }

        ModuleInstallCommonsLib.onInstall(
            validationConfig.module(), installData, type(IValidationModule).interfaceId
        );
        emit ValidationInstalled(validationConfig.module(), validationConfig.entityId());
    }

    function _uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallDatas
    ) internal {
        ValidationStorage storage _validationStorage =
            getAccountStorage().validationStorage[ValidationLocatorLib.moduleEntityToLookupKey(validationFunction)];
        bool onUninstallSuccess = true;

        // Send `onUninstall` to hooks
        if (hookUninstallDatas.length > 0) {
            HookConfig[] memory execHooks = MemManagementLib.loadExecHooks(_validationStorage);
            HookConfig[] memory validationHooks = MemManagementLib.loadValidationHooks(_validationStorage);

            // If any uninstall data is provided, assert it is of the correct length.
            if (hookUninstallDatas.length != validationHooks.length + execHooks.length) {
                revert ArrayLengthMismatch();
            }

            // Hook uninstall data is provided in the order of pre validation hooks, then execution hooks.
            uint256 hookIndex = 0;
            uint256 length = validationHooks.length;
            for (uint256 i = 0; i < length; ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                (address hookModule,) = ModuleEntityLib.unpack(validationHooks[i].moduleEntity());
                onUninstallSuccess =
                    onUninstallSuccess && ModuleInstallCommonsLib.onUninstall(hookModule, hookData);
                hookIndex++;
            }

            length = execHooks.length;
            for (uint256 i = 0; i < length; ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                address hookModule = execHooks[i].module();
                onUninstallSuccess =
                    onUninstallSuccess && ModuleInstallCommonsLib.onUninstall(hookModule, hookData);
                hookIndex++;
            }
        }

        // Clear all stored hooks. The lengths of the hooks are cleared in `_removeValidationFunction`.
        _validationStorage.validationHooks.clear();
        _validationStorage.executionHooks.clear();

        // Clear selectors
        _validationStorage.selectors.clear();

        // Clear validation function data.
        // Must be done at the end, because the hook lengths are accessed in the loop above.
        _removeValidationFunction(_validationStorage);

        (address module, uint32 entityId) = ModuleEntityLib.unpack(validationFunction);
        onUninstallSuccess = onUninstallSuccess && ModuleInstallCommonsLib.onUninstall(module, uninstallData);

        emit ValidationUninstalled(module, entityId, onUninstallSuccess);
    }
}
