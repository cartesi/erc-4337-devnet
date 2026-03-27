// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {SemiModularAccountStorageOnly} from "src/account/SemiModularAccountStorageOnly.sol";

contract DeployScript is Script {
    function run() external {
        vmSafe.startBroadcast();
        _deploy(
            type(SemiModularAccountStorageOnly).name,
            type(SemiModularAccountStorageOnly).creationCode,
            abi.encode(
                _loadDeployment("../../../eth-infinitism/entrypoint/0.7", "EntryPoint"),
                _loadDeployment("../../modular-account/2.0.0", "ExecutionInstallDelegate")
            ),
            0x0000000000000000000000000000000000000000927a62077526ff6711e02ca3
        );
        vmSafe.stopBroadcast();
    }
}
