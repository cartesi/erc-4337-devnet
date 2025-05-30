// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {CastLib} from "modular-account/helpers/CastLib.sol";
import {SetValue} from "modular-account/libraries/Constants.sol";
import {LinkedListSet, LinkedListSetLib} from "modular-account/libraries/LinkedListSetLib.sol";

import {BaseLightAccount} from "./common/BaseLightAccount.sol";
import {CustomSlotInitializable} from "./common/CustomSlotInitializable.sol";

/// @title A simple ERC-4337 compatible smart contract account with one or more designated owner accounts.
/// @dev Like LightAccount, but multiple owners are supported. The account is initialized with a list of owners,
/// and the `updateOwners` method can be used to add or remove owners.
contract MultiOwnerLightAccount is BaseLightAccount, CustomSlotInitializable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using LinkedListSetLib for LinkedListSet;
    using CastLib for address;
    using CastLib for SetValue[];

    /// @dev The version used for namespaced storage is not linked to the release version of the contract. Storage
    /// versions will be updated only when storage layout changes are made.
    /// keccak256(abi.encode(uint256(keccak256("multi_owner_light_account_v1.storage")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant _STORAGE_POSITION = 0x0eb5184329babcda7203727c83eff940fb292fc735f61720a6182b755bf7f900;
    /// @dev keccak256(abi.encode(uint256(keccak256("multi_owner_light_account_v1.initializable")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant _INITIALIZABLE_STORAGE_POSITION =
        0xaa296a366a62f6551d3ddfceae892d1791068a359a0d3461aab99dfc6c5fd700;

    struct LightAccountStorage {
        LinkedListSet owners;
    }

    /// @notice Emitted when this account is first initialized.
    /// @param entryPoint The entry point.
    /// @param owners The initial owners.
    event LightAccountInitialized(IEntryPoint indexed entryPoint, address[] owners);

    /// @notice This event is emitted when owners of the account are updated. Also emitted once at initialization, with
    /// an empty `removedOwners`.
    /// @param addedOwners The address array of added owners.
    /// @param removedOwners The address array of removed owners.
    event OwnersUpdated(address[] addedOwners, address[] removedOwners);

    /// @dev The account is not allowed to have 0 owners.
    error EmptyOwnersNotAllowed();

    /// @dev The owner to be added is not valid (e.g., `address(0)`, the account itself, or a current owner).
    error InvalidOwner(address owner);

    /// @dev The owner to be removed does not exist.
    error OwnerDoesNotExist(address owner);

    constructor(IEntryPoint entryPoint_) CustomSlotInitializable(_INITIALIZABLE_STORAGE_POSITION) {
        _ENTRY_POINT = entryPoint_;
        _disableInitializers();
    }

    /// @notice Called once as part of initialization, either during initial deployment or when first upgrading to
    /// this contract.
    /// @dev The `_ENTRY_POINT` member is immutable, to reduce gas consumption. To update the entry point address, a new
    /// implementation of LightAccount must be deployed with the new entry point address, and then `upgradeToAndCall`
    /// must be called to upgrade the implementation.
    /// @param owners_ The initial owners of the account.
    function initialize(address[] calldata owners_) public virtual initializer {
        _initialize(owners_);
    }

    /// @notice Update owners of the account. Can only be called by a current owner or from the entry point via
    /// a user operation signed by a current owner.
    /// @dev If an owner is present in both `ownersToAdd` and `ownersToRemove`, it will be added as owner. The owner
    /// array cannot have 0 or duplicate addresses.
    /// @param ownersToAdd The address array of owners to be added.
    /// @param ownersToRemove The address array of owners to be removed.
    function updateOwners(address[] memory ownersToAdd, address[] memory ownersToRemove)
        external
        virtual
        onlyAuthorized
    {
        _updateOwners(ownersToAdd, ownersToRemove);
    }

    ///@notice Return the owners of this account.
    ///@return The array of owner addresses.
    function owners() public view returns (address[] memory) {
        return _getStorage().owners.getAll().toAddressArray();
    }

    function _initialize(address[] calldata owners_) internal virtual {
        emit LightAccountInitialized(_ENTRY_POINT, owners_);
        _updateOwners(owners_, new address[](0));
    }

    function _updateOwners(address[] memory ownersToAdd, address[] memory ownersToRemove) internal {
        _removeOwnersOrRevert(ownersToRemove);
        _addOwnersOrRevert(ownersToAdd);

        if (_getStorage().owners.isEmpty()) {
            revert EmptyOwnersNotAllowed();
        }

        emit OwnersUpdated(ownersToAdd, ownersToRemove);
    }

    function _addOwnersOrRevert(address[] memory ownersToAdd) internal {
        LightAccountStorage storage _storage = _getStorage();
        uint256 length = ownersToAdd.length;
        for (uint256 i = 0; i < length; ++i) {
            address ownerToAdd = ownersToAdd[i];
            if (ownerToAdd == address(this) || !_storage.owners.tryAdd(ownerToAdd.toSetValue())) {
                revert InvalidOwner(ownerToAdd);
            }
        }
    }

    function _removeOwnersOrRevert(address[] memory ownersToRemove) internal {
        LightAccountStorage storage _storage = _getStorage();
        uint256 length = ownersToRemove.length;
        for (uint256 i = 0; i < length; ++i) {
            if (!_storage.owners.tryRemove(ownersToRemove[i].toSetValue())) {
                revert OwnerDoesNotExist(ownersToRemove[i]);
            }
        }
    }

    /// @dev Implement template method of BaseAccount.
    /// Uses a modified version of `SignatureChecker.isValidSignatureNow` in which the digest is wrapped with an
    /// "Ethereum Signed Message" envelope for the EOA-owner case but not in the ERC-1271 contract-owner case.
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        if (userOp.signature.length < 1) {
            revert InvalidSignatureType();
        }
        uint8 signatureType = uint8(userOp.signature[0]);
        if (signatureType == uint8(SignatureType.EOA)) {
            // EOA signature
            bytes32 signedHash = userOpHash.toEthSignedMessageHash();
            bytes memory signature = userOp.signature[1:];
            return _successToValidationData(_isValidEOAOwnerSignature(signedHash, signature));
        } else if (signatureType == uint8(SignatureType.CONTRACT_WITH_ADDR)) {
            // Contract signature with address
            address contractOwner = address(bytes20(userOp.signature[1:21]));
            bytes memory signature = userOp.signature[21:];
            return _successToValidationData(_isValidContractOwnerSignatureNow(contractOwner, userOpHash, signature));
        }
        revert InvalidSignatureType();
    }

    /// @notice Check if the signature is a valid by an EOA owner for the given digest.
    /// @dev Only supports 65-byte signatures, and uses the digest directly. Reverts if the signature is malformed.
    /// @param digest The digest to be checked.
    /// @param signature The signature to be checked.
    /// @return True if the signature is valid and by an owner, false otherwise.
    function _isValidEOAOwnerSignature(bytes32 digest, bytes memory signature) internal view returns (bool) {
        address recovered = digest.recover(signature);
        return _getStorage().owners.contains(recovered.toSetValue());
    }

    /// @notice Check if the given verifier is a contract owner, and if the signature is a valid ERC-1271 signature by
    /// a contract owner for the given digest.
    /// @param contractOwner The address of the contract owner.
    /// @param digest The digest to be checked.
    /// @param signature The signature to be checked.
    /// @return True if the signature is valid and by an owner, false otherwise.
    function _isValidContractOwnerSignatureNow(address contractOwner, bytes32 digest, bytes memory signature)
        internal
        view
        returns (bool)
    {
        return SignatureChecker.isValidERC1271SignatureNow(contractOwner, digest, signature)
            && _getStorage().owners.contains(contractOwner.toSetValue());
    }

    /// @dev The signature is valid if it is signed by the owner's private key (if the owner is an EOA) or if it is a
    /// valid ERC-1271 signature from the owner (if the owner is a contract). Reverts if the signature is malformed.
    /// Note that unlike the signature validation used in `validateUserOp`, this does **not** wrap the hash in an
    /// "Ethereum Signed Message" envelope before checking the signature in the EOA-owner case.
    function _isValidSignature(bytes32 replaySafeHash, bytes calldata signature)
        internal
        view
        virtual
        override
        returns (bool)
    {
        if (signature.length < 1) {
            revert InvalidSignatureType();
        }
        uint8 signatureType = uint8(signature[0]);
        if (signatureType == uint8(SignatureType.EOA)) {
            // EOA signature
            return _isValidEOAOwnerSignature(replaySafeHash, signature[1:]);
        } else if (signatureType == uint8(SignatureType.CONTRACT_WITH_ADDR)) {
            // Contract signature with address
            address contractOwner = address(bytes20(signature[1:21]));
            return _isValidContractOwnerSignatureNow(contractOwner, replaySafeHash, signature[21:]);
        }
        revert InvalidSignatureType();
    }

    function _domainNameAndVersion()
        internal
        view
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "MultiOwnerLightAccount";
        // Set to the major version of the GitHub release at which the contract was last updated.
        version = "2";
    }

    function _isFromOwner() internal view virtual override returns (bool) {
        return _getStorage().owners.contains(msg.sender.toSetValue());
    }

    function _getStorage() internal pure returns (LightAccountStorage storage storageStruct) {
        bytes32 position = _STORAGE_POSITION;
        assembly ("memory-safe") {
            storageStruct.slot := position
        }
    }
}
