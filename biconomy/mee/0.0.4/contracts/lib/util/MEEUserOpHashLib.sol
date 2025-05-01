// SPDX-License-Identifier: Unlicense
/*
 * @title MEE UserOp Hash Lib
 *
 * @dev Calculates userOp hash for the new type of transaction - SuperTransaction (as a part of MEE stack)
 */
pragma solidity ^0.8.27;

library MEEUserOpHashLib {
    /**
     * Calculates userOp hash. Almost works like a regular 4337 userOp hash with few fields added.
     *
     * @param userOpHash userOp hash to calculate the hash for
     * @param lowerBoundTimestamp lower bound timestamp set when constructing userOp
     * @param upperBoundTimestamp upper bound timestamp set when constructing userOp
     * Timestamps are used by the MEE node to schedule the execution of the userOps within the superTx
     */
    function getMEEUserOpHash(bytes32 userOpHash, uint256 lowerBoundTimestamp, uint256 upperBoundTimestamp)
        internal
        pure
        returns (bytes32 meeUserOpHash)
    {
        meeUserOpHash =
            keccak256(bytes.concat(keccak256(abi.encode(userOpHash, lowerBoundTimestamp, upperBoundTimestamp))));
    }
}
