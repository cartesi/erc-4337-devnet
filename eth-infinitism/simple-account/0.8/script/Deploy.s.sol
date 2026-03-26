// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {SimpleAccountFactory} from "contracts/accounts/SimpleAccountFactory.sol";
import {Simple7702Account} from "contracts/accounts/Simple7702Account.sol";
import {IEntryPoint} from "contracts/interfaces/IEntryPoint.sol";

contract DeployScript is Script {
    function run() external {
        vmSafe.startBroadcast();
        _deploy(
            type(SimpleAccountFactory).name,
            type(SimpleAccountFactory).creationCode,
            abi.encode(_loadDeployment("../../entrypoint/0.8", "EntryPoint"))
        );
        _deploy(
            type(Simple7702Account).name,
            type(Simple7702Account).creationCode
        );
        vmSafe.stopBroadcast();
    }
}
