// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {PimlicoEntryPointSimulations} from "src/PimlicoEntryPointSimulations.sol";

contract DeployScript is Script {
    function run() external {
        vmSafe.startBroadcast();
        _deploy(
            type(PimlicoEntryPointSimulations).name,
            type(PimlicoEntryPointSimulations).creationCode,
            0x3132333400000000000000000000000000000000000000000000000000000000
        );
        vmSafe.stopBroadcast();
    }
}
