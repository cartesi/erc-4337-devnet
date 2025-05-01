// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.27;

// Had to keep it copypasted as the og lib https://github.com/bakaoh/solidity-rlp-encode has incompatible solc version

import "byteslib/BytesLib.sol";

/**
 * @title RLPEncoder
 * @dev A simple RLP encoding library.
 * @author Bakaoh
 */
library RLPEncoder {
    using BytesLib for bytes;

    /*
     * Internal functions
     */

    /**
     * @dev RLP encodes a byte string.
     * @param self The byte string to encode.
     * @return The RLP encoded string in bytes.
     */
    function encodeBytes(bytes memory self) internal pure returns (bytes memory) {
        bytes memory encoded;
        if (self.length == 1 && uint8(self[0]) < 128) {
            encoded = self;
        } else {
            encoded = encodeLength(self.length, 128).concat(self);
        }
        return encoded;
    }

    /**
     * @dev RLP encodes a uint.
     * @param self The uint to encode.
     * @return The RLP encoded uint in bytes.
     */
    function encodeUint(uint256 self) internal pure returns (bytes memory) {
        return encodeBytes(toBinary(self));
    }

    /**
     * @dev Encode the first byte, followed by the `len` in binary form if `length` is more than 55.
     * @param self The length of the string or the payload.
     * @param offset 128 if item is string, 192 if item is list.
     * @return RLP encoded bytes.
     */
    function encodeLength(uint256 self, uint256 offset) internal pure returns (bytes memory) {
        bytes memory encoded;
        if (self < 56) {
            encoded = new bytes(1);
            encoded[0] = bytes32(self + offset)[31];
        } else {
            uint256 lenLen;
            uint256 i = 1;
            while (self / i != 0) {
                lenLen++;
                i *= 256;
            }

            encoded = new bytes(lenLen + 1);
            encoded[0] = bytes32(lenLen + offset + 55)[31];
            for (i = 1; i <= lenLen; i++) {
                encoded[i] = bytes32((self / (256 ** (lenLen - i))) % 256)[31];
            }
        }
        return encoded;
    }

    /*
     * Private functions
     */

    /**
     * @dev Encode integer in big endian binary form with no leading zeroes.
     * @notice TODO: This should be optimized with assembly to save gas costs.
     * @param _x The integer to encode.
     * @return RLP encoded bytes.
     */
    function toBinary(uint256 _x) private pure returns (bytes memory) {
        bytes memory b = new bytes(32);
        assembly {
            mstore(add(b, 32), _x)
        }
        uint256 i;
        for (i = 0; i < 32; i++) {
            if (b[i] != 0) {
                break;
            }
        }
        bytes memory res = new bytes(32 - i);
        for (uint256 j = 0; j < res.length; j++) {
            res[j] = b[i++];
        }
        return res;
    }
}
