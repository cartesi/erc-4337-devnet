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

import {IExecutionHookModule} from "@erc6900/reference-implementation/interfaces/IExecutionHookModule.sol";
import {IExecutionModule} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {IModule} from "@erc6900/reference-implementation/interfaces/IModule.sol";
import {IValidationHookModule} from "@erc6900/reference-implementation/interfaces/IValidationHookModule.sol";
import {IValidationModule} from "@erc6900/reference-implementation/interfaces/IValidationModule.sol";
import {IAggregator} from "@eth-infinitism/account-abstraction/interfaces/IAggregator.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";

/// @title Known Selectors Library
/// @author Alchemy
/// @notice Library to help to check if a selector is an ERC-6900 module function or a an ERC-4337 contract
/// function.
library KnownSelectorsLib {
    /// @notice Check if a selector is an ERC-4337 function.
    /// @param selector The selector to check.
    /// @return True if the selector is an ERC-4337 function, false otherwise.
    function isERC4337Function(uint32 selector) internal pure returns (bool) {
        return selector == uint32(IAggregator.validateSignatures.selector)
            || selector == uint32(IAggregator.validateUserOpSignature.selector)
            || selector == uint32(IAggregator.aggregateSignatures.selector)
            || selector == uint32(IPaymaster.validatePaymasterUserOp.selector)
            || selector == uint32(IPaymaster.postOp.selector);
    }

    /// @notice Check if a selector is an ERC-6900 module function.
    /// @param selector The selector to check.
    /// @return True if the selector is an ERC-6900 module function, false otherwise.
    function isIModuleFunction(uint32 selector) internal pure returns (bool) {
        return selector == uint32(IModule.onInstall.selector) || selector == uint32(IModule.onUninstall.selector)
            || selector == uint32(IModule.moduleId.selector)
            || selector == uint32(IExecutionModule.executionManifest.selector)
            || selector == uint32(IExecutionHookModule.preExecutionHook.selector)
            || selector == uint32(IExecutionHookModule.postExecutionHook.selector)
            || selector == uint32(IValidationModule.validateUserOp.selector)
            || selector == uint32(IValidationModule.validateRuntime.selector)
            || selector == uint32(IValidationModule.validateSignature.selector)
            || selector == uint32(IValidationHookModule.preUserOpValidationHook.selector)
            || selector == uint32(IValidationHookModule.preRuntimeValidationHook.selector)
            || selector == uint32(IValidationHookModule.preSignatureValidationHook.selector);
    }
}
