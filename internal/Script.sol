// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

interface VmSafe {
    function assertGt(uint256, uint256, string calldata) external pure;
    function assertTrue(bool, string calldata) external pure;
    function computeCreate2Address(bytes32, bytes32, address) external pure returns (address);
    function createDir(string calldata, bool) external;
    function parseJsonAddress(string calldata, string calldata) external pure returns (address);
    function readFile(string calldata) external view returns (string memory);
    function readFileBinary(string calldata) external view returns (bytes memory);
    function rpc(string calldata, string calldata) external returns (bytes memory);
    function serializeAddress(string calldata, string calldata, address) external returns (string memory);
    function serializeString(string calldata, string calldata, string calldata) external returns (string memory);
    function startBroadcast() external;
    function startBroadcast(address) external;
    function stopBroadcast() external;
    function toString(address) external pure returns (string memory);
    function toString(uint256) external pure returns (string memory);
    function writeJson(string calldata, string calldata) external;
}

abstract contract Script {
    VmSafe constant vmSafe = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// @notice Deterministically deploy a contract (or skip if already deployed)
    /// and store the deployment in a JSON file indexed by the current chain ID.
    /// @param contractName The contract name
    /// @param creationCode The creation code of the contract
    /// @dev Uses the empty byte array as constructor arguments and bytes32(0) as salt.
    function _deploy(
        string memory contractName,
        bytes memory creationCode
    ) internal returns (address) {
        return _deploy(
            contractName,
            creationCode,
            abi.encode()
        );
    }

    /// @notice Deterministically deploy a contract (or skip if already deployed)
    /// and store the deployment in a JSON file indexed by the current chain ID.
    /// @param contractName The contract name
    /// @param creationCode The creation code of the contract
    /// @param constructorArgs The ABI-encoded constructor arguments
    /// @dev Uses bytes32(0) as salt.
    function _deploy(
        string memory contractName,
        bytes memory creationCode,
        bytes memory constructorArgs
    ) internal returns (address) {
        return _deploy(
            contractName,
            creationCode,
            constructorArgs,
            bytes32(0)
        );
    }

    /// @notice Deterministically deploy a contract (or skip if already deployed)
    /// and store the deployment in a JSON file indexed by the current chain ID.
    /// @param contractName The contract name
    /// @param creationCode The creation code of the contract
    /// @param salt The CREATE2 salt argument
    /// @dev Uses the empty byte array as constructor arguments.
    function _deploy(
        string memory contractName,
        bytes memory creationCode,
        bytes32 salt
    ) internal returns (address deployment) {
        return _deploy(
            contractName,
            creationCode,
            abi.encode(),
            salt
        );
    }

    /// @notice Deterministically deploy a contract (or skip if already deployed)
    /// and store the deployment in a JSON file indexed by the current chain ID.
    /// @param contractName The contract name
    /// @param creationCode The creation code of the contract
    /// @param constructorArgs The ABI-encoded constructor arguments
    /// @param salt The CREATE2 salt argument
    function _deploy(
        string memory contractName,
        bytes memory creationCode,
        bytes memory constructorArgs,
        bytes32 salt
    ) internal returns (address deployment) {
        bytes memory initCode = abi.encodePacked(creationCode, constructorArgs);
        deployment = vmSafe.computeCreate2Address(salt, keccak256(initCode), CREATE2_FACTORY);
        if (deployment.code.length == 0) {
            bytes memory payload = abi.encodePacked(salt, initCode);
            (bool success,) = CREATE2_FACTORY.call(payload);
            vmSafe.assertTrue(success, "CREATE2 factory raised an error");
            vmSafe.assertGt(deployment.code.length, 0, "CREATE2 factory did not deploy contract");
        }
        string memory deploymentStr = vmSafe.toString(deployment);
        string memory objectKey = string.concat(contractName, "@", deploymentStr);
        string memory json;
        json = vmSafe.serializeAddress(objectKey, "address", deployment);
        json = vmSafe.serializeString(objectKey, "contractName", contractName);
        string memory dir = _getCurrentChainDeploymentsDir(".");
        vmSafe.createDir(dir, true);
        string memory path = _getDeploymentFilePath(dir, contractName);
        vmSafe.writeJson(json, path);
    }

    /// @notice Load a deployment from a JSON file.
    /// @param projectRoot The project root path
    /// @param contractName The contract name
    /// @return deployment The deployment address
    function _loadDeployment(string memory projectRoot, string memory contractName)
        internal
        view
        returns (address deployment)
    {
        string memory dir = _getCurrentChainDeploymentsDir(projectRoot);
        string memory path = _getDeploymentFilePath(dir, contractName);
        string memory json = vmSafe.readFile(path);
        deployment = vmSafe.parseJsonAddress(json, ".address");
        if (deployment.code.length == 0) {
            revert(
                string.concat(
                    contractName,
                    " is not deployed at ",
                    vmSafe.toString(deployment)
                )
            );
        }
    }

    /// @notice Get the deployment directory of a project given the current chain.
    /// @param projectRoot The project root path
    /// @return The project's deployments directory for the current chain
    function _getCurrentChainDeploymentsDir(string memory projectRoot)
        internal
        view
        returns (string memory)
    {
        return string.concat(
            projectRoot,
            "/deployments/",
            vmSafe.toString(block.chainid)
        );
    }

    /// @notice Get the path of a deployment file given the directory and contract name.
    /// @param dir The deployment directory (see `_getCurrentChainDeploymentsDir`)
    /// @param contractName The contract name
    /// @return The deployment file path
    function _getDeploymentFilePath(string memory dir, string memory contractName)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            dir,
            "/",
            contractName,
            ".json"
        );
    }
}
