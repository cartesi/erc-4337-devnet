// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {EntryPoint} from "contracts/core/EntryPoint.sol";

contract DeployScript is Script {
    function run() external {
        vmSafe.startBroadcast();
        _deploy(
            type(EntryPoint).name,
            type(EntryPoint).creationCode,
            0x90d8084deab30c2a37c45e8d47f49f2f7965183cb6990a98943ef94940681de3
        );
        vmSafe.stopBroadcast();
    }
}
