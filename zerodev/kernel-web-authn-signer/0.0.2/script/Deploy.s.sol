// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {WebAuthnSigner} from "src/WebAuthnSigner.sol";

contract DeployScript is Script {
    function run() external {
        _loadDeployment("../../../daimo/p256-verifier/1.0.0", "P256Verifier"); // ensure P256Verifier is deployed
        vmSafe.startBroadcast();
        _deploy(type(WebAuthnSigner).name, type(WebAuthnSigner).creationCode);
        vmSafe.stopBroadcast();
    }
}
