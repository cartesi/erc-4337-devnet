// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ECDSA} from "solady/utils/ECDSA.sol";

library EcdsaLib {
    using ECDSA for bytes32;

    /**
     * @dev Solady ECDSA does not revert on incorrect signatures.
     *      Instead, it returns address(0) as the recovered address.
     *      Make sure to never pass address(0) as expectedSigner to this function.
     */
    function isValidSignature(address expectedSigner, bytes32 hash, bytes memory signature)
        internal
        view
        returns (bool)
    {
        if (hash.tryRecover(signature) == expectedSigner) return true;
        if (hash.toEthSignedMessageHash().tryRecover(signature) == expectedSigner) return true;
        return false;
    }
}
