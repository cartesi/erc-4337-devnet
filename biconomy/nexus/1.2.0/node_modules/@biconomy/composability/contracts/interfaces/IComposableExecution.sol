// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

import {ComposableExecution} from "../types/ComposabilityDataTypes.sol";

interface IComposableExecution {
    function executeComposable(ComposableExecution[] calldata executions) external payable;
}

interface IComposableExecutionModule is IComposableExecution {
    function executeComposableCall(ComposableExecution[] calldata executions) external;
    function executeComposableDelegateCall(ComposableExecution[] calldata executions) external;
}
