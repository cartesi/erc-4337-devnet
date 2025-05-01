// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IValidator, MODULE_TYPE_VALIDATOR} from "erc7579/interfaces/IERC7579Module.sol";
import {ISessionValidator} from "contracts/interfaces/ISessionValidator.sol";
import {EnumerableSet} from "EnumerableSet4337/EnumerableSet4337.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ERC7739Validator} from "erc7739Validator/ERC7739Validator.sol";
import {
    SIG_TYPE_SIMPLE,
    SIG_TYPE_ON_CHAIN,
    SIG_TYPE_ERC20_PERMIT,
    EIP1271_SUCCESS,
    EIP1271_FAILED,
    MODULE_TYPE_STATELESS_VALIDATOR,
    SIG_TYPE_MEE_FLOW
} from "contracts/types/Constants.sol";
// Fusion libraries - validate userOp using on-chain tx or off-chain permit
import {PermitValidatorLib} from "contracts/lib/fusion/PermitValidatorLib.sol";
import {TxValidatorLib} from "contracts/lib/fusion/TxValidatorLib.sol";
import {SimpleValidatorLib} from "contracts/lib/fusion/SimpleValidatorLib.sol";
import {NoMeeFlowLib} from "contracts/lib/fusion/NoMeeFlowLib.sol";
import {EcdsaLib} from "contracts/lib/util/EcdsaLib.sol";
/**
 * @title K1MeeValidator
 * @dev   An ERC-7579 validator (module type 1) and stateless validator (module type 7) for the MEE stack.
 *        Supports 3 MEE modes:
 *        - Simple (Super Tx hash is signed)
 *        - On-chain Tx (Super Tx hash is appended to a regular txn and signed)
 *        - ERC-2612 Permit (Super Tx hash is pasted into deadline field of the ERC-2612 Permit and signed)
 *
 *        Further improvements:
 *        - Further gas optimizations
 *        - Use EIP-712 to make superTx hash not blind => use 7739 for the MEE 1271 flows
 *
 *        Using erc7739 for MEE flows makes no sense currently because user signs blind hashes anyways
 *        (except permit mode, but the superTx hash is still blind in it).
 *        So we just hash smart account address into the og hash for 1271 MEE flow currently.
 *        In future full scale 7739 will replace it when superTx hash is 712 and transparent.
 *
 */

contract K1MeeValidator is IValidator, ISessionValidator, ERC7739Validator {
    using EnumerableSet for EnumerableSet.AddressSet;
    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Mapping of smart account addresses to their respective owner addresses
    mapping(address => address) public smartAccountOwners;

    /// @notice Set of safe senders for each smart account
    EnumerableSet.AddressSet private _safeSenders;

    /// @notice Error to indicate that no owner was provided during installation
    error NoOwnerProvided();

    /// @notice Error to indicate that the new owner cannot be the zero address
    error ZeroAddressNotAllowed();

    /// @notice Error to indicate the module is already initialized
    error ModuleAlreadyInitialized();

    /// @notice Error to indicate that the new owner cannot be a contract address
    error NewOwnerIsContract();

    /// @notice Error to indicate that the owner cannot be the zero address
    error OwnerCannotBeZeroAddress();

    /// @notice Error to indicate that the data length is invalid
    error InvalidDataLength();

    /// @notice Error to indicate that the safe senders length is invalid
    error SafeSendersLengthInvalid();

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Initialize the module with the given data
     *
     * @param data The data to initialize the module with
     */
    function onInstall(bytes calldata data) external override {
        require(data.length != 0, NoOwnerProvided());
        require(!_isInitialized(msg.sender), ModuleAlreadyInitialized());
        address newOwner = address(bytes20(data[:20]));
        require(newOwner != address(0), OwnerCannotBeZeroAddress());
        require(!_isContract(newOwner), NewOwnerIsContract());
        smartAccountOwners[msg.sender] = newOwner;
        if (data.length > 20) {
            _fillSafeSenders(data[20:]);
        }
    }

    /**
     * De-initialize the module with the given data
     */
    function onUninstall(bytes calldata) external override {
        delete smartAccountOwners[msg.sender];
        _safeSenders.removeAll(msg.sender);
    }

    /// @notice Transfers ownership of the validator to a new owner
    /// @param newOwner The address of the new owner
    function transferOwnership(address newOwner) external {
        require(newOwner != address(0), ZeroAddressNotAllowed());
        require(!_isContract(newOwner), NewOwnerIsContract());
        smartAccountOwners[msg.sender] = newOwner;
    }

    /**
     * Check if the module is initialized
     * @param smartAccount The smart account to check
     *
     * @return true if the module is initialized, false otherwise
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    /// @notice Adds a safe sender to the _safeSenders list for the smart account
    function addSafeSender(address sender) external {
        _safeSenders.add(msg.sender, sender);
    }

    /// @notice Removes a safe sender from the _safeSenders list for the smart account
    function removeSafeSender(address sender) external {
        _safeSenders.remove(msg.sender, sender);
    }

    /// @notice Checks if a sender is in the _safeSenders list for the smart account
    function isSafeSender(address sender, address smartAccount) external view returns (bool) {
        return _safeSenders.contains(smartAccount, sender);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Validates PackedUserOperation
     *
     * @param userOp UserOperation to be validated
     * @param userOpHash Hash of the UserOperation to be validated
     * @dev fallback flow => non MEE flow => no dedicated prefix introduced for the sake of compatibility.
     *      It may lead to a case where some signature turns out to have first bytes matching the prefix.
     *      However, this is very unlikely to happen and even if it does, the consequences are just
     *      that the signature is not validated which is easily solved by altering userOp => hash => sig.
     *
     * @return uint256 the result of the signature validation, which can be:
     *  - 0 if the signature is valid
     *  - 1 if the signature is invalid
     *  - <20-byte> aggregatorOrSigFail, <6-byte> validUntil and <6-byte> validAfter (see ERC-4337
     * for more details)
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        override
        returns (uint256)
    {
        bytes4 sigType = bytes4(userOp.signature[0:4]);
        address owner = getOwner(userOp.sender);

        if (sigType == SIG_TYPE_SIMPLE) {
            return SimpleValidatorLib.validateUserOp(userOpHash, userOp.signature[4:], owner);
        } else if (sigType == SIG_TYPE_ON_CHAIN) {
            return TxValidatorLib.validateUserOp(userOpHash, userOp.signature[4:], owner);
        } else if (sigType == SIG_TYPE_ERC20_PERMIT) {
            return PermitValidatorLib.validateUserOp(userOpHash, userOp.signature[4:], owner);
        } else {
            // fallback flow => non MEE flow => no prefix
            return NoMeeFlowLib.validateUserOp(userOpHash, userOp.signature, owner);
        }
    }

    /**
     * Validates an ERC-1271 signature
     *
     * @param sender The sender of the ERC-1271 call to the account
     * @param hash The hash of the message
     * @param signature The signature of the message
     *
     * @return sigValidationResult the result of the signature validation, which can be:
     *  - EIP1271_SUCCESS if the signature is valid
     *  - EIP1271_FAILED if the signature is invalid
     */
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata signature)
        external
        view
        virtual
        override
        returns (bytes4 sigValidationResult)
    {
        if (bytes3(signature[0:3]) != SIG_TYPE_MEE_FLOW) {
            // Non MEE 7739 flow
            // goes to ERC7739Validator to apply 7739 magic and then returns back
            // to this contract's _erc1271IsValidSignatureNowCalldata() method.
            return _erc1271IsValidSignatureWithSender(sender, hash, _erc1271UnwrapSignature(signature));
        } else {
            // non-7739 flow
            // hash the SA into the `hash` to protect against two SA's with same owner vector
            return _validateSignatureForOwner(
                getOwner(msg.sender), keccak256(abi.encodePacked(hash, msg.sender)), _erc1271UnwrapSignature(signature)
            ) ? EIP1271_SUCCESS : EIP1271_FAILED;
        }
    }

    /// @notice ISessionValidator interface for smart session
    /// @param hash The hash of the data to validate
    /// @param sig The signature data
    /// @param data The data to validate against (owner address in this case)
    function validateSignatureWithData(bytes32 hash, bytes calldata sig, bytes calldata data)
        external
        view
        returns (bool validSig)
    {
        require(data.length >= 20, InvalidDataLength());
        return _validateSignatureForOwner(address(bytes20(data[:20])), hash, sig);
    }

    /**
     * Get the owner of the smart account
     * @param smartAccount The address of the smart account
     * @return The owner of the smart account
     */
    function getOwner(address smartAccount) public view returns (address) {
        address owner = smartAccountOwners[smartAccount];
        return owner == address(0) ? smartAccount : owner;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Returns the name of the module
    /// @return The name of the module
    function name() external pure returns (string memory) {
        return "K1MeeValidator";
    }

    /// @notice Returns the version of the module
    /// @return The version of the module
    function version() external pure returns (string memory) {
        return "1.0.1";
    }

    /// @notice Checks if the module is of the specified type
    /// @param typeId The type ID to check
    /// @return True if the module is of the specified type, false otherwise
    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == MODULE_TYPE_VALIDATOR || typeId == MODULE_TYPE_STATELESS_VALIDATOR;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Internal method that does the job of validating the signature via ECDSA (secp256k1)
    /// @param owner The address of the owner
    /// @param hash The hash of the data to validate
    /// @param signature The signature data
    function _validateSignatureForOwner(address owner, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        bytes4 sigType = bytes4(signature[0:4]);

        if (sigType == SIG_TYPE_SIMPLE) {
            return SimpleValidatorLib.validateSignatureForOwner(owner, hash, signature[4:]);
        } else if (sigType == SIG_TYPE_ON_CHAIN) {
            return TxValidatorLib.validateSignatureForOwner(owner, hash, signature[4:]);
        } else if (sigType == SIG_TYPE_ERC20_PERMIT) {
            return PermitValidatorLib.validateSignatureForOwner(owner, hash, signature[4:]);
        } else {
            // fallback flow => non MEE flow => no prefix
            return NoMeeFlowLib.validateSignatureForOwner(owner, hash, signature);
        }
    }

    /// @notice Checks if the smart account is initialized with an owner
    /// @param smartAccount The address of the smart account
    /// @return True if the smart account has an owner, false otherwise
    function _isInitialized(address smartAccount) private view returns (bool) {
        return smartAccountOwners[smartAccount] != address(0);
    }

    // @notice Fills the _safeSenders list from the given data
    function _fillSafeSenders(bytes calldata data) private {
        require(data.length % 20 == 0, SafeSendersLengthInvalid());
        for (uint256 i; i < data.length / 20; i++) {
            _safeSenders.add(msg.sender, address(bytes20(data[20 * i:20 * (i + 1)])));
        }
    }

    /// @notice Checks if the address is a contract
    /// @param account The address to check
    /// @return True if the address is a contract, false otherwise
    function _isContract(address account) private view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /// @dev Returns whether the `hash` and `signature` are valid.
    ///      Obtains the authorized signer's credentials and calls some
    ///      module's specific internal function to validate the signature
    ///      against credentials.
    function _erc1271IsValidSignatureNowCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        override
        returns (bool)
    {
        // call custom internal function to validate the signature against credentials
        return EcdsaLib.isValidSignature(getOwner(msg.sender), hash, signature);
    }

    /// @dev Returns whether the `sender` is considered safe, such
    /// that we don't need to use the nested EIP-712 workflow.
    /// See: https://mirror.xyz/curiousapple.eth/pFqAdW2LiJ-6S4sg_u1z08k4vK6BCJ33LcyXpnNb8yU
    // The canonical `MulticallerWithSigner` at 0x000000000000D9ECebf3C23529de49815Dac1c4c
    // is known to include the account in the hash to be signed.
    // msg.sender = Smart Account
    // sender = 1271 og request sender
    function _erc1271CallerIsSafe(address sender) internal view virtual override returns (bool) {
        return (
            sender == 0x000000000000D9ECebf3C23529de49815Dac1c4c // MulticallerWithSigner
                || sender == msg.sender // Smart Account. Assume smart account never sends non safe eip-712 struct
                || _safeSenders.contains(msg.sender, sender)
        ); // check if sender is in _safeSenders for the Smart Account
    }
}
