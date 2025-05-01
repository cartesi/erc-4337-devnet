// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ComposableExecutionLib} from "./ComposableExecutionLib.sol";
import {InputParam, OutputParam, ComposableExecution, Constraint, ConstraintType, InputParamFetcherType, OutputParamFetcherType} from "./types/ComposabilityDataTypes.sol";
import {IComposableExecution} from "./interfaces/IComposableExecution.sol";

abstract contract ComposableExecutionBase is IComposableExecution {
    using ComposableExecutionLib for InputParam[];
    using ComposableExecutionLib for OutputParam[];

    /// @dev Override it in the account and introduce additional access control or other checks
    function executeComposable(ComposableExecution[] calldata executions) external payable virtual;

    /// @dev internal function to execute the composable execution flow
    /// First, processes the input parameters and returns the composed calldata
    /// Then, executes the action
    /// Then, processes the output parameters
    function _executeComposable(ComposableExecution[] calldata executions) internal {
        uint256 length = executions.length;
        for (uint256 i; i < length; i++) {
            ComposableExecution calldata execution = executions[i];
            bytes memory composedCalldata = execution.inputParams.processInputs(execution.functionSig);
            bytes memory returnData;
            if (execution.to != address(0)) {
                returnData = _executeAction(execution.to, execution.value, composedCalldata);
            } else {
                returnData = new bytes(0);
            }
            execution.outputParams.processOutputs(returnData, address(this));
        }
    }

    /// @dev Override this in the account
    /// using account's native execution approach
    function _executeAction(address to, uint256 value, bytes memory data)
        internal
        virtual
        returns (bytes memory returnData);
}
