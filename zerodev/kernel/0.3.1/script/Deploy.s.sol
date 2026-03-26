// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {Kernel} from "src/Kernel.sol";
import {KernelFactory} from "src/factory/KernelFactory.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";

interface IFactoryStaker {
    function approveFactory(KernelFactory factory, bool approval) external payable;
    function approved(KernelFactory factory) external view returns (bool);
}

contract DeployScript is Script {
    address constant OWNER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    uint256 constant MIN_OWNER_BALANCE = 1 ether;

    function run() external {
        vmSafe.startBroadcast();
        Kernel kernel = Kernel(
            payable(
                _deploy(
                    type(Kernel).name,
                    type(Kernel).creationCode,
                    abi.encode(
                        _loadDeployment(
                            "../../../eth-infinitism/entrypoint/0.7",
                            "EntryPoint"
                        )
                    )
                )
            )
        );
        KernelFactory kernelFactory = KernelFactory(
            _deploy(
                type(KernelFactory).name,
                type(KernelFactory).creationCode,
                abi.encode(kernel)
            )
        );
        _deploy(
            type(ECDSAValidator).name,
            type(ECDSAValidator).creationCode
        );
        vmSafe.stopBroadcast();

        IFactoryStaker factoryStaker = IFactoryStaker(
            _loadDeployment(
                "../../kernel-factory-staker/0.3",
                "FactoryStaker"
            )
        );

        if (!factoryStaker.approved(kernelFactory)) {
            if (OWNER.balance < MIN_OWNER_BALANCE) {
                vmSafe.startBroadcast();
                (bool success,) = OWNER.call{value: MIN_OWNER_BALANCE}("");
                vmSafe.stopBroadcast();
                vmSafe.assertTrue(success, "Could not fund FactoryStaker owner");
            }

            vmSafe.rpc(
                "anvil_impersonateAccount",
                string.concat("[\"", vmSafe.toString(OWNER), "\"]")
            );

            vmSafe.startBroadcast(OWNER);
            factoryStaker.approveFactory(kernelFactory, true);
            vmSafe.stopBroadcast();
        }
    }
}
