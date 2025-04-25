# ERC-4337 devnet

This repository contains copies of ERC-4337 infrastructure smart contracts that can be deployed to a local devnet (anvil), so developers can develop application locally before moving to testnet or mainnet.

We understand that the most common ways of replicating live chains locally are:

- use `anvil` [forking capability](https://book.getfoundry.sh/guides/forking-mainnet-with-cast-anvil);
- or use `anvil_setCode` method to force the bytecode into a specify address with the bytecode obtained from the live network.

We however take a different approach.

As most contracts use [deterministic deployment](https://book.getfoundry.sh/guides/deterministic-deployments-using-create2), we compile all smart contracts from source using the same settings as deployed to the live network, and deploy using the same salt, resulting in the same address.
The contracts are usually downloaded from verified deployments from ethereum, using the `forge clone` command.

The local deployment is handled using [cannon](https://usecannon.com), which provides more composability.

## Building

```shell
npm install -g @usecannon/cli
make install-foundry
make
```

## Cannon packages

- [eth-infinitism-entrypoint:0.6.0](https://usecannon.com/packages/eth-infinitism-entrypoint/0.6.0/13370-main) ([source](https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.6.0))
- [eth-infinitism-entrypoint:0.7.0](https://usecannon.com/packages/eth-infinitism-entrypoint/0.7.0/13370-main) ([source](https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.7.0))
- [eth-infinitism-entrypoint:0.8.0](https://usecannon.com/packages/eth-infinitism-entrypoint/0.8.0/13370-main) ([source](https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.8.0))
- [eth-infinitism-simple-account:0.6.0](https://usecannon.com/packages/eth-infinitism-simple-account/0.6.0/13370-main) ([source](https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.6.0))
- [eth-infinitism-simple-account:0.7.0](https://usecannon.com/packages/eth-infinitism-simple-account/0.7.0/13370-main) ([source](https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.7.0))
- [pimlico-entrypoint-simulations:0.7.0](https://usecannon.com/packages/pimlico-entrypoint-simulations/0.7.0/13370-main) ([source](https://github.com/pimlicolabs/contracts))
- [zerodev-factory-staker:3](https://usecannon.com/packages/zerodev-factory-staker/3/13370-main) ([source](https://github.com/zerodevapp/kernel/releases/tag/v3.0))
- [zerodev-kernel:3.0](https://usecannon.com/packages/zerodev-kernel/3.0/13370-main) ([source](https://github.com/zerodevapp/kernel/releases/tag/v3.0))
- [zerodev-kernel:3.1](https://usecannon.com/packages/zerodev-kernel/3.1/13370-main) ([source](https://github.com/zerodevapp/kernel/releases/tag/v3.1))
- [zerodev-kernel:3.2](https://usecannon.com/packages/zerodev-kernel/3.2/13370-main) ([source](https://github.com/zerodevapp/kernel/releases/tag/v3.2))
- [alchemy-light-account:1.1.0](https://usecannon.com/packages/alchemy-light-account/1.1.0/13370-main) ([source](https://github.com/alchemyplatform/light-account/releases/tag/v1.1.0))
- [alchemy-light-account:2.0.0](https://usecannon.com/packages/alchemy-light-account/2.0.0/13370-main) ([source](https://github.com/alchemyplatform/light-account/releases/tag/v2.0.0))
- [alchemy-modular-account:2.0.0](https://usecannon.com/packages/alchemy-modular-account/2.0.0/13370-main) ([source](https://github.com/alchemyplatform/modular-account/releases/tag/v2.0.0))

## Useful tools

- forge clone --help
- cast run --help
- cast create2 --help
- https://playground.sourcify.dev
