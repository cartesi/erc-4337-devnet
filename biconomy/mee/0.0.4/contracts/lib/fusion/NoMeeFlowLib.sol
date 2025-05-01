// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "account-abstraction/interfaces/PackedUserOperation.sol";
import "account-abstraction/core/Helpers.sol";
import "../util/EcdsaLib.sol";

library NoMeeFlowLib {
    /**
     * Standard userOp validator - validates by simply checking if the userOpHash was signed by the account's EOA owner.
     *
     * @param userOpHash userOpHash being validated.
     * @param parsedSignature Signature
     * @param expectedSigner Signer expected to be recovered
     */
    function validateUserOp(bytes32 userOpHash, bytes memory parsedSignature, address expectedSigner)
        internal
        view
        returns (uint256)
    {
        if (!EcdsaLib.isValidSignature(expectedSigner, userOpHash, parsedSignature)) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    /**
     * @notice Validates the signature against the expected signer (owner)
     * @param expectedSigner Signer expected to be recovered
     * @param hash Hash of the userOp
     * @param parsedSignature Signature
     */
    function validateSignatureForOwner(address expectedSigner, bytes32 hash, bytes memory parsedSignature)
        internal
        view
        returns (bool)
    {
        return EcdsaLib.isValidSignature(expectedSigner, hash, parsedSignature);
    }
}
