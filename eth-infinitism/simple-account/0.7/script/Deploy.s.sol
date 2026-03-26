// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {IEntryPoint} from "contracts/interfaces/IEntryPoint.sol";
import {SimpleAccountFactory} from "contracts/samples/SimpleAccountFactory.sol";

contract DeployScript is Script {
    function run() external {
        vmSafe.startBroadcast();
        _deploy(
            type(SimpleAccountFactory).name,
            type(SimpleAccountFactory).creationCode,
            abi.encode(_loadDeployment("../../entrypoint/0.7", "EntryPoint"))
        );
        vmSafe.stopBroadcast();
    }
}
