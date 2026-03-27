// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {RateLimitPolicy} from "src/RateLimitPolicy.sol";

contract DeployScript is Script {
    function run() external {
        vmSafe.startBroadcast();
        _deploy(type(RateLimitPolicy).name, type(RateLimitPolicy).creationCode);
        vmSafe.stopBroadcast();
    }
}
