// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {MerkleProof} from "openzeppelin/utils/cryptography/MerkleProof.sol";
import {RLPReader as RLPDecoder} from "rlp-reader/RLPReader.sol";
import {RLPEncoder} from "../rlp/RLPEncoder.sol";
import {MEEUserOpHashLib} from "../util/MEEUserOpHashLib.sol";
import {EcdsaLib} from "../util/EcdsaLib.sol";
import {BytesLib} from "byteslib/BytesLib.sol";
import "account-abstraction/core/Helpers.sol";

/**
 * @dev Library to validate the signature for MEE on-chain Txn mode
 *      This is the mode where superTx hash is appended to a regular txn (legacy or 1559) calldata
 *      Type 1 (EIP-2930) transactions are not supported.
 *      The whole txn is signed along with the superTx hash
 *      Txn is executed prior to a superTx, so it can pass some funds from the EOA to the smart account
 *      For more details see Fusion docs:
 *      - https://ethresear.ch/t/fusion-module-7702-alternative-with-no-protocol-changes/20949
 *      - https://docs.biconomy.io/explained/eoa#fusion-module
 *      @dev Some smart contracts may not be able to consume the txn with bytes32 appended to the calldata.
 *           However this is very small subset. One of the cases when it can happen is when the smart contract
 *           is has separate receive() and fallback() functions. Then if a txn is a value transfer, it will
 *           be expected to be consumed by the receive() function. However, if there's bytes32 appended to the calldata,
 *           it will be consumed by the fallback() function which may not be expected. In this case, the provided
 *           contracts/forwarder/Forwarder.sol can be used to 'clear' the bytes32 from the calldata.
 *      @dev In theory, the last 32 bytes of calldata from any transaction by the EOA can be interpreted as
 *           a superTx hash. Even if it was not assumed. This introduces the potential risk of phishing attacks
 *           where the user may unknowingly sign a transaction where the last 32 bytes of the calldata end up
 *           being a superTx hash. However, it is not easy to craft a txn that makes sense for a user and allows
 *           arbitrary bytes32 as last 32 bytes. Thus, wallets and users should be aware of this potential risk
 *           and should not sign txns where the last 32 bytes of the calldata do not belong to the function arguments
 *           and are just appended at the end.
 */
library TxValidatorLib {
    uint8 constant LEGACY_TX_TYPE = 0x00;
    uint8 constant EIP1559_TX_TYPE = 0x02;

    uint8 constant EIP_155_MIN_V_VALUE = 37;
    uint8 constant HASH_BYTE_SIZE = 32;

    uint8 constant TIMESTAMP_BYTE_SIZE = 6;
    uint8 constant PROOF_ITEM_BYTE_SIZE = 32;
    uint8 constant ITX_HASH_BYTE_SIZE = 32;

    using RLPDecoder for RLPDecoder.RLPItem;
    using RLPDecoder for bytes;
    using RLPEncoder for uint256;
    using BytesLib for bytes;

    struct TxData {
        uint8 txType;
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes32 utxHash;
        bytes32 superTxHash;
        bytes32[] proof;
        uint48 lowerBoundTimestamp;
        uint48 upperBoundTimestamp;
    }

    // To save a bit of gas, not pass timestamps where not needed
    struct TxDataShort {
        uint8 txType;
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes32 utxHash;
        bytes32 superTxHash;
        bytes32[] proof;
    }

    struct TxParams {
        uint256 v;
        bytes32 r;
        bytes32 s;
        bytes callData;
    }

    /**
     * This function parses the given userOpSignature into a valid fully signed EVM transaction.
     * Once parsed, the function will check for three conditions:
     *      1. is the userOp part of the superTX merkle tree
     *      2. is the recovered tx signer equal to the expected signer?
     *      3. is the given UserOp a part of the merkle tree
     *
     * If all the conditions are met - outside contract can be sure that the expected signer has indeed
     * approved the given hash by performing given on-chain transaction.
     *
     * NOTES: This function will revert if either of following is met:
     *    1. the userOpSignature couldn't be parsed to a valid fully signed EVM transaction
     *    2. hash couldn't be extracted from the tx.data
     *    3. extracted hash wasn't equal to the provided expected hash
     *    4. recovered signer wasn't equal to the expected signer
     *
     * @param userOpHash UserOp hash being validated.
     * @param parsedSignature Signature provided as the userOp.signature parameter (minus the prepended tx type byte).
     *                        Expecting to receive fully signed serialized EVM transaction here of type 0x00 (LEGACY)
     *                        or 0x02 (EIP1556).
     *                        For LEGACY tx type the "0x00" prefix has to be added manually while the EIP1559 tx type
     *                        already contains 0x02 prefix.
     * @param expectedSigner Expected EOA signer of the given EVM transaction => superTX.
     */
    function validateUserOp(bytes32 userOpHash, bytes calldata parsedSignature, address expectedSigner)
        internal
        view
        returns (uint256)
    {
        TxData memory decodedTx = decodeTx(parsedSignature);

        bytes32 meeUserOpHash =
            MEEUserOpHashLib.getMEEUserOpHash(userOpHash, decodedTx.lowerBoundTimestamp, decodedTx.upperBoundTimestamp);

        bytes memory signature = abi.encodePacked(decodedTx.r, decodedTx.s, decodedTx.v);
        if (!EcdsaLib.isValidSignature(expectedSigner, decodedTx.utxHash, signature)) {
            return SIG_VALIDATION_FAILED;
        }

        if (!MerkleProof.verify(decodedTx.proof, decodedTx.superTxHash, meeUserOpHash)) {
            return SIG_VALIDATION_FAILED;
        }

        return _packValidationData(false, decodedTx.upperBoundTimestamp, decodedTx.lowerBoundTimestamp);
    }

    /**
     * @dev validate the signature for the owner of the superTx
     *      used fot the 1271 flow and for the stateless validators (erc7579 module type 7)
     * @param expectedSigner the expected signer of the superTx
     * @param dataHash the hash of the data to be signed
     * @param parsedSignature the signature to be validated
     * @return true if the signature is valid, false otherwise
     */
    function validateSignatureForOwner(address expectedSigner, bytes32 dataHash, bytes calldata parsedSignature)
        internal
        view
        returns (bool)
    {
        TxDataShort memory decodedTx = decodeTxShort(parsedSignature);

        bytes memory signature = abi.encodePacked(decodedTx.r, decodedTx.s, decodedTx.v);

        if (!EcdsaLib.isValidSignature(expectedSigner, decodedTx.utxHash, signature)) {
            return false;
        }

        if (!MerkleProof.verify(decodedTx.proof, decodedTx.superTxHash, dataHash)) {
            return false;
        }
        return true;
    }

    function decodeTx(bytes calldata self) internal pure returns (TxData memory) {
        uint8 txType = uint8(self[0]); //first byte is tx type
        uint48 lowerBoundTimestamp =
            uint48(bytes6((self[self.length - 2 * TIMESTAMP_BYTE_SIZE:self.length - TIMESTAMP_BYTE_SIZE])));
        uint48 upperBoundTimestamp = uint48(bytes6(self[self.length - TIMESTAMP_BYTE_SIZE:]));
        uint8 proofItemsCount = uint8(self[self.length - 2 * TIMESTAMP_BYTE_SIZE - 1]);
        uint256 appendedDataLen = (uint256(proofItemsCount) * PROOF_ITEM_BYTE_SIZE + 1) + 2 * TIMESTAMP_BYTE_SIZE;
        bytes calldata rlpEncodedTx = self[1:self.length - appendedDataLen];
        RLPDecoder.RLPItem memory parsedRlpEncodedTx = rlpEncodedTx.toRlpItem();
        RLPDecoder.RLPItem[] memory parsedRlpEncodedTxItems = parsedRlpEncodedTx.toList();
        TxParams memory params = extractParams(txType, parsedRlpEncodedTxItems);

        return TxData(
            txType,
            _adjustV(params.v),
            params.r,
            params.s,
            calculateUnsignedTxHash(txType, rlpEncodedTx, parsedRlpEncodedTx.payloadLen(), params.v, params.r, params.s),
            extractAppendedHash(params.callData),
            extractProof(self, proofItemsCount),
            lowerBoundTimestamp,
            upperBoundTimestamp
        );
    }

    function decodeTxShort(bytes calldata self) internal pure returns (TxDataShort memory) {
        uint8 txType = uint8(self[0]); //first byte is tx type
        uint8 proofItemsCount = uint8(self[self.length - 1]);
        uint256 appendedDataLen = (uint256(proofItemsCount) * PROOF_ITEM_BYTE_SIZE + 1);
        bytes calldata rlpEncodedTx = self[1:self.length - appendedDataLen];
        RLPDecoder.RLPItem memory parsedRlpEncodedTx = rlpEncodedTx.toRlpItem();
        RLPDecoder.RLPItem[] memory parsedRlpEncodedTxItems = parsedRlpEncodedTx.toList();
        TxParams memory params = extractParams(txType, parsedRlpEncodedTxItems);

        return TxDataShort(
            txType,
            _adjustV(params.v),
            params.r,
            params.s,
            calculateUnsignedTxHash(txType, rlpEncodedTx, parsedRlpEncodedTx.payloadLen(), params.v, params.r, params.s),
            extractAppendedHash(params.callData),
            extractProofShort(self, proofItemsCount)
        );
    }

    function extractParams(uint8 txType, RLPDecoder.RLPItem[] memory items)
        private
        pure
        returns (TxParams memory params)
    {
        uint8 dataPos;
        uint8 vPos;
        uint8 rPos;
        uint8 sPos;

        if (txType == LEGACY_TX_TYPE) {
            dataPos = 5;
            vPos = 6;
            rPos = 7;
            sPos = 8;
        } else if (txType == EIP1559_TX_TYPE) {
            dataPos = 7;
            vPos = 9;
            rPos = 10;
            sPos = 11;
        } else {
            revert("TxValidatorLib:: unsupported evm tx type");
        }

        return TxParams(
            items[vPos].toUint(), bytes32(items[rPos].toUint()), bytes32(items[sPos].toUint()), items[dataPos].toBytes()
        );
    }

    function extractAppendedHash(bytes memory callData) private pure returns (bytes32 iTxHash) {
        if (callData.length < ITX_HASH_BYTE_SIZE) revert("TxDecoder:: callData length too short");
        iTxHash = bytes32(callData.slice(callData.length - ITX_HASH_BYTE_SIZE, ITX_HASH_BYTE_SIZE));
    }

    function extractProof(bytes calldata signedTx, uint8 proofItemsCount)
        private
        pure
        returns (bytes32[] memory proof)
    {
        proof = new bytes32[](proofItemsCount);
        uint256 pos = signedTx.length - 2 * TIMESTAMP_BYTE_SIZE - 1;
        for (proofItemsCount; proofItemsCount > 0; proofItemsCount--) {
            proof[proofItemsCount - 1] = bytes32(signedTx[pos - PROOF_ITEM_BYTE_SIZE:pos]);
            pos = pos - PROOF_ITEM_BYTE_SIZE;
        }
    }

    function extractProofShort(bytes calldata signedTx, uint8 proofItemsCount)
        private
        pure
        returns (bytes32[] memory proof)
    {
        proof = new bytes32[](proofItemsCount);
        uint256 pos = signedTx.length - 1;
        for (proofItemsCount; proofItemsCount > 0; proofItemsCount--) {
            proof[proofItemsCount - 1] = bytes32(signedTx[pos - PROOF_ITEM_BYTE_SIZE:pos]);
            pos = pos - PROOF_ITEM_BYTE_SIZE;
        }
    }

    function calculateUnsignedTxHash(
        uint8 txType,
        bytes memory rlpEncodedTx,
        uint256 rlpEncodedTxPayloadLen,
        uint256 v,
        bytes32 r,
        bytes32 s
    ) private pure returns (bytes32 hash) {
        uint256 totalSignatureSize =
            uint256(r).encodeUint().length + uint256(s).encodeUint().length + v.encodeUint().length;
        uint256 totalPrefixSize = rlpEncodedTx.length - rlpEncodedTxPayloadLen;
        bytes memory rlpEncodedTxNoSigAndPrefix =
            rlpEncodedTx.slice(totalPrefixSize, rlpEncodedTx.length - totalSignatureSize - totalPrefixSize);
        if (txType == EIP1559_TX_TYPE) {
            return keccak256(abi.encodePacked(txType, prependRlpContentSize(rlpEncodedTxNoSigAndPrefix, "")));
        } else if (txType == LEGACY_TX_TYPE) {
            if (v >= EIP_155_MIN_V_VALUE) {
                return keccak256(
                    prependRlpContentSize(
                        rlpEncodedTxNoSigAndPrefix,
                        abi.encodePacked(
                            uint256(_extractChainIdFromV(v)).encodeUint(),
                            uint256(0).encodeUint(),
                            uint256(0).encodeUint()
                        )
                    )
                );
            } else {
                return keccak256(prependRlpContentSize(rlpEncodedTxNoSigAndPrefix, ""));
            }
        } else {
            revert("TxValidatorLib:: unsupported tx type");
        }
    }

    function prependRlpContentSize(bytes memory content, bytes memory extraData) public pure returns (bytes memory) {
        bytes memory combinedContent = abi.encodePacked(content, extraData);
        return abi.encodePacked(combinedContent.length.encodeLength(RLPDecoder.LIST_SHORT_START), combinedContent);
    }

    function _adjustV(uint256 v) internal pure returns (uint8) {
        if (v >= EIP_155_MIN_V_VALUE) {
            return uint8((v - 2 * _extractChainIdFromV(v) - 35) + 27);
        } else if (v <= 1) {
            return uint8(v + 27);
        } else {
            return uint8(v);
        }
    }

    function _extractChainIdFromV(uint256 v) internal pure returns (uint256 chainId) {
        chainId = (v - 35) / 2;
    }
}
