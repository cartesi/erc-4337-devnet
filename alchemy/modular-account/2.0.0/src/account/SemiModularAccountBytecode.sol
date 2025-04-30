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

import {IModularAccount} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {ExecutionInstallDelegate} from "../helpers/ExecutionInstallDelegate.sol";
import {SemiModularAccountBase} from "./SemiModularAccountBase.sol";

/// @title Semi-Modular Account Bytecode
/// @author Alchemy
/// @notice An implementation of a semi-modular account which reads the signer from proxy bytecode if it is not
/// disabled and zero in storage.
/// @dev Inherits SemiModularAccountBase. This account requires that its proxy is compliant with Solady's LibClone
/// ERC1967WithImmutableArgs bytecode with a bytecode-appended address (should be encodePacked) to be used as the
/// fallback signer.
contract SemiModularAccountBytecode is SemiModularAccountBase {
    constructor(IEntryPoint entryPoint, ExecutionInstallDelegate executionInstallDelegate)
        SemiModularAccountBase(entryPoint, executionInstallDelegate)
    {}

    /// @inheritdoc IModularAccount
    function accountId() external pure override returns (string memory) {
        return "alchemy.sma-bytecode.1.0.0";
    }

    /// @dev If the fallback signer is set in storage, we ignore the bytecode signer.
    function _retrieveFallbackSignerUnchecked(SemiModularAccountStorage storage _storage)
        internal
        view
        override
        returns (address)
    {
        address storageFallbackSigner = _storage.fallbackSigner;
        if (storageFallbackSigner != address(0)) {
            return storageFallbackSigner;
        }

        // If the signer in storage is zero, default to
        bytes memory appendedData = LibClone.argsOnERC1967(address(this), 0, 20);

        return address(uint160(bytes20(appendedData)));
    }
}
