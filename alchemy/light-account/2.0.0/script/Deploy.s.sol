// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";

interface IBaseLightAccountFactory {
    function addStake(uint32 unstakeDelay, uint256 amount) external payable;
}

contract DeployScript is Script {
    address constant OWNER = 0xDdF32240B4ca3184De7EC8f0D5Aba27dEc8B7A5C;
    uint256 constant STAKE = 0.10 ether;

    function run() external {
        address entryPoint = _loadDeployment(
            "../../../eth-infinitism/entrypoint/0.7",
            "EntryPoint"
        );

        vmSafe.startBroadcast();
        address lightAccountFactory = _deploy(
            "LightAccountFactory",
            vmSafe.readFileBinary("data/LightAccountFactory.bin"),
            abi.encode(OWNER, entryPoint),
            0x00000000000000000000000000000000000000005f1ffd9d31306e056bcc959b
        );
        _deploy(
            "MultiOwnerLightAccountFactory",
            vmSafe.readFileBinary("data/MultiOwnerLightAccountFactory.bin"),
            abi.encode(OWNER, entryPoint),
            0x0000000000000000000000000000000000000000bb3ab048b3f4ef2620ea0163
        );
        vmSafe.stopBroadcast();

        IStakeManager.DepositInfo memory info = IEntryPoint(entryPoint).getDepositInfo(lightAccountFactory);

        if (info.stake < STAKE) {
            uint256 stakeNeeded = STAKE - info.stake;

            vmSafe.startBroadcast();
            (bool success,) = OWNER.call{value: stakeNeeded + 1 ether}("");
            vmSafe.assertTrue(success, "Could not fund LightAccountFactory owner");
            vmSafe.stopBroadcast();

            vmSafe.rpc(
                "anvil_impersonateAccount",
                string.concat("[\"", vmSafe.toString(OWNER), "\"]")
            );

            vmSafe.startBroadcast(OWNER);
            IBaseLightAccountFactory(payable(lightAccountFactory)).addStake{value: stakeNeeded}(86400, stakeNeeded);
            vmSafe.stopBroadcast();
        }
    }
}
