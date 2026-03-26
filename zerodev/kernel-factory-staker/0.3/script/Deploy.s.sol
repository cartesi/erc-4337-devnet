// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {FactoryStaker} from "src/factory/FactoryStaker.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";
import {IStakeManager} from "src/interfaces/IStakeManager.sol";

contract DeployScript is Script {
    address constant OWNER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    uint256 constant STAKE = 0.10 ether;

    function run() external {
        vmSafe.startBroadcast();
        FactoryStaker factoryStaker = FactoryStaker(
            _deploy(
                type(FactoryStaker).name,
                type(FactoryStaker).creationCode,
                abi.encode(OWNER)
            )
        );
        vmSafe.stopBroadcast();

        IEntryPoint entryPoint = IEntryPoint(
            _loadDeployment(
                "../../../eth-infinitism/entrypoint/0.7",
                "EntryPoint"
            )
        );

        IStakeManager.DepositInfo memory info =
            entryPoint.getDepositInfo(address(factoryStaker));

        if (info.stake < STAKE) {
            uint256 stakeNeeded = STAKE - info.stake;

            vmSafe.startBroadcast();
            (bool success,) = OWNER.call{value: stakeNeeded + 1 ether}("");
            vmSafe.assertTrue(success, "Could not fund FactoryStaker owner");
            vmSafe.stopBroadcast();

            vmSafe.rpc(
                "anvil_impersonateAccount",
                string.concat("[\"", vmSafe.toString(OWNER), "\"]")
            );

            vmSafe.startBroadcast(OWNER);
            factoryStaker.stake{value: stakeNeeded}(entryPoint, 86400);
            vmSafe.stopBroadcast();
        }
    }
}
