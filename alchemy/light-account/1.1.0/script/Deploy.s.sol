// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {LightAccountFactory} from "src/LightAccountFactory.sol";

contract DeployScript is Script {
    function run() external {
        address entryPoint = _loadDeployment(
            "../../../eth-infinitism/entrypoint/0.6",
            "EntryPoint"
        );

        vmSafe.startBroadcast();
        _deploy(
            type(LightAccountFactory).name,
            type(LightAccountFactory).creationCode,
            abi.encode(entryPoint),
            0x4e59b44847b379578588920ca78fbf26c0b4956c5528f3e2f146000008fabf77
        );
        vmSafe.stopBroadcast();
    }
}
