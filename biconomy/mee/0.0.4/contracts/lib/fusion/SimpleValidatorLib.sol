// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {MerkleProof} from "openzeppelin/utils/cryptography/MerkleProof.sol";
import {EcdsaLib} from "../util/EcdsaLib.sol";
import {MEEUserOpHashLib} from "../util/MEEUserOpHashLib.sol";
import "account-abstraction/core/Helpers.sol";

/**
 * @dev Library to validate the signature for MEE Simple mode
 *      In this mode, Fusion is not involved and just the superTx hash is signed
 */
library SimpleValidatorLib {
    /**
     * This function parses the given userOpSignature into a Supertransaction signature
     *
     * Once parsed, the function will check for two conditions:
     *      1. is the root supertransaction hash signed by the account owner's EOA
     *      2. is the userOp actually a part of the given supertransaction
     *      by checking the leaf based on this userOpHash is a part of the merkle tree represented by root hash = superTxHash
     *
     * If both conditions are met - outside contract can be sure that the expected signer has indeed
     * approved the given userOp - and the userOp is successfully validate.
     *
     * @param userOpHash UserOp hash being validated.
     * @param signatureData Signature provided as the userOp.signature parameter (minus the prepended tx type byte).
     * @param expectedSigner Signer expected to be recovered when decoding the ERC20OPermit signature.
     */
    function validateUserOp(bytes32 userOpHash, bytes calldata signatureData, address expectedSigner)
        internal
        view
        returns (uint256)
    {
        bytes32 superTxHash;
        uint48 lowerBoundTimestamp;
        uint48 upperBoundTimestamp;
        bytes32[] calldata proof;
        bytes calldata secp256k1Signature;

        assembly {
            superTxHash := calldataload(signatureData.offset)
            lowerBoundTimestamp := calldataload(add(signatureData.offset, 0x20))
            upperBoundTimestamp := calldataload(add(signatureData.offset, 0x40))
            let u := calldataload(add(signatureData.offset, 0x60))
            let s := add(signatureData.offset, u)
            proof.offset := add(s, 0x20)
            proof.length := calldataload(s)
            u := mul(proof.length, 0x20)
            s := add(proof.offset, u)
            secp256k1Signature.offset := add(s, 0x20)
            secp256k1Signature.length := calldataload(s)
        }

        bytes32 leaf = MEEUserOpHashLib.getMEEUserOpHash(userOpHash, lowerBoundTimestamp, upperBoundTimestamp);
        if (!EcdsaLib.isValidSignature(expectedSigner, superTxHash, secp256k1Signature)) {
            return SIG_VALIDATION_FAILED;
        }

        if (!MerkleProof.verify(proof, superTxHash, leaf)) {
            return SIG_VALIDATION_FAILED;
        }

        return _packValidationData(false, upperBoundTimestamp, lowerBoundTimestamp);
    }

    /**
     * @notice Validates the signature against the expected signer (owner)
     * @param owner Signer expected to be recovered
     * @param dataHash data hash being validated.
     * @param signatureData Signature
     */
    function validateSignatureForOwner(address owner, bytes32 dataHash, bytes calldata signatureData)
        internal
        view
        returns (bool)
    {
        bytes32 superTxHash;
        bytes32[] calldata proof;
        bytes calldata secp256k1Signature;

        assembly {
            superTxHash := calldataload(signatureData.offset)
            let u := calldataload(add(signatureData.offset, 0x20))
            let s := add(signatureData.offset, u)
            proof.offset := add(s, 0x20)
            proof.length := calldataload(s)
            u := mul(proof.length, 0x20)
            s := add(proof.offset, u)
            secp256k1Signature.offset := add(s, 0x20)
            secp256k1Signature.length := calldataload(s)
        }

        if (!EcdsaLib.isValidSignature(owner, superTxHash, secp256k1Signature)) {
            return false;
        }

        if (!MerkleProof.verify(proof, superTxHash, dataHash)) {
            return false;
        }

        return true;
    }
}
