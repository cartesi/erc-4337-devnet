# ERC-4337 devnet

This repository contains copies of ERC-4337 infrastructure smart contracts that can be deployed to a local devnet (anvil), so developers can develop application locally before moving to testnet.

The contracts are usually downloaded from verified deployments from ethereum, using the `forge clone` command. The foundry projects contains settings that try to match the deployed version settings, so the bytecodes match 100%.

As most contracts use deterministic deployment, it's possible to deploy them locally to `anvil` and have the same address as they do on ethereum. This helps with developers, because they don't need to change application settings when moving from devnet to testnet to mainnet.

The local deployment is handled using [cannon](https://usecannon.com), a cool deployment tool.