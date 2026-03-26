// (c) Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.8;

import {Script} from "script/../../../../internal/Script.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IStakeManager} from "account-abstraction/interfaces/IStakeManager.sol";
import {ExecutionInstallDelegate} from "src/helpers/ExecutionInstallDelegate.sol";
import {ModularAccount} from "src/account/ModularAccount.sol";
import {SemiModularAccountBytecode} from "src/account/SemiModularAccountBytecode.sol";
import {SemiModularAccount7702} from "src/account/SemiModularAccount7702.sol";
import {SingleSignerValidationModule} from "src/modules/validation/SingleSignerValidationModule.sol";
import {WebAuthnValidationModule} from "src/modules/validation/WebAuthnValidationModule.sol";
import {AccountFactory} from "src/factory/AccountFactory.sol";
import {AllowlistModule} from "src/modules/permissions/AllowlistModule.sol";
import {NativeTokenLimitModule} from "src/modules/permissions/NativeTokenLimitModule.sol";
import {PaymasterGuardModule} from "src/modules/permissions/PaymasterGuardModule.sol";
import {TimeRangeModule} from "src/modules/permissions/TimeRangeModule.sol";

contract DeployScript is Script {
    address constant OWNER = 0xDdF32240B4ca3184De7EC8f0D5Aba27dEc8B7A5C;
    uint256 constant STAKE = 0.10 ether;

    function run() external {
        address entryPoint = _loadDeployment(
            "../../../eth-infinitism/entrypoint/0.7",
            "EntryPoint"
        );

        vmSafe.startBroadcast();
        address executionInstallDelegate = _deploy(
            type(ExecutionInstallDelegate).name,
            type(ExecutionInstallDelegate).creationCode,
            0x0000000000000000000000000000000000000000f025c5072701275be9e38d72
        );
        address modularAccount = _deploy(
            type(ModularAccount).name,
            type(ModularAccount).creationCode,
            abi.encode(entryPoint, executionInstallDelegate),
            0x000000000000000000000000000000000000000026d724645fb0ae7579e98c62
        );
        address semiModularAccountBytecode = _deploy(
            type(SemiModularAccountBytecode).name,
            type(SemiModularAccountBytecode).creationCode,
            abi.encode(entryPoint, executionInstallDelegate),
            0x0000000000000000000000000000000000000000d5ec084a831ef551abb05bc7
        );
        _deploy(
            type(SemiModularAccount7702).name,
            type(SemiModularAccount7702).creationCode,
            abi.encode(entryPoint, executionInstallDelegate),
            0x560d523fd8061660acf1839f13f8550b0910ad69cf928acafea0cd76936f3800
        );
        address singleSignerValidationModule = _deploy(
            type(SingleSignerValidationModule).name,
            type(SingleSignerValidationModule).creationCode,
            0x000000000000000000000000000000000000000021f94598c3ee4349df132fca
        );
        address webAuthnValidationModule = _deploy(
            type(WebAuthnValidationModule).name,
            type(WebAuthnValidationModule).creationCode,
            0x0000000000000000000000000000000000000000d6fcd2d895007352212d092c
        );
        address accountFactory = _deploy(
            type(AccountFactory).name,
            type(AccountFactory).creationCode,
            abi.encode(
                entryPoint,
                modularAccount,
                semiModularAccountBytecode,
                singleSignerValidationModule,
                webAuthnValidationModule,
                OWNER
            ),
            0x0000000000000000000000000000000000000000620c1b8944951c0586e48adb
        );
        _deploy(
            type(AllowlistModule).name,
            type(AllowlistModule).creationCode,
            0x000000000000000000000000000000000000000053327e2d907120557b948d91
        );
        _deploy(
            type(NativeTokenLimitModule).name,
            type(NativeTokenLimitModule).creationCode,
            0x0000000000000000000000000000000000000000cd5d40e42713cb5f4b81d828
        );
        _deploy(
            type(PaymasterGuardModule).name,
            type(PaymasterGuardModule).creationCode,
            0x00000000000000000000000000000000000000001c0a1f2f2ba4a325db87a323
        );
        _deploy(
            type(TimeRangeModule).name,
            type(TimeRangeModule).creationCode,
            0x0000000000000000000000000000000000000000500e1dfd80787c342371e513
        );
        vmSafe.stopBroadcast();

        IStakeManager.DepositInfo memory info = IEntryPoint(entryPoint).getDepositInfo(accountFactory);

        if (info.stake < STAKE) {
            uint256 stakeNeeded = STAKE - info.stake;

            vmSafe.startBroadcast();
            (bool success,) = OWNER.call{value: stakeNeeded + 1 ether}("");
            vmSafe.assertTrue(success, "Could not fund AccountFactory owner");
            vmSafe.stopBroadcast();

            vmSafe.rpc(
                "anvil_impersonateAccount",
                string.concat("[\"", vmSafe.toString(OWNER), "\"]")
            );

            vmSafe.startBroadcast(OWNER);
            AccountFactory(accountFactory).addStake{value: stakeNeeded}(86400);
            vmSafe.stopBroadcast();
        }
    }
}
