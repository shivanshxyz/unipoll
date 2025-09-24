// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseHook} from "@openzeppelin/uniswap-hooks/src/base/BaseHook.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IPoolManager, SwapParams} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";

interface IGroupSwapVerifier {
    function verifyExecution(uint256 pollId, uint256 amountIn, uint256 minOut, address initiator)
        external
        view
        returns (bool);
}

/// @notice Minimal hook that authorizes swaps only when initiated via GroupSwap contract
contract GroupSwapHook is BaseHook {
    IGroupSwapVerifier public immutable groupSwap;

    constructor(IPoolManager _poolManager, address _groupSwap) BaseHook(_poolManager) {
        groupSwap = IGroupSwapVerifier(_groupSwap);
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // hookData encoding: abi.encode(pollId, amountIn, minOut, initiator)
    function _beforeSwap(address, PoolKey calldata, SwapParams calldata params, bytes calldata hookData)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        (uint256 pollId, uint256 amountIn, uint256 minOut, address initiator) =
            abi.decode(hookData, (uint256, uint256, uint256, address));

        // Direction determines which amountSpecified is used; we enforce absolute value equality on amountIn
        uint256 specified = params.amountSpecified < 0
            ? uint256(int256(-params.amountSpecified))
            : uint256(int256(params.amountSpecified));

        require(specified == amountIn, "GroupSwapHook: amountIn mismatch");
        require(groupSwap.verifyExecution(pollId, amountIn, minOut, initiator), "GroupSwapHook: unauthorized");

        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, BalanceDelta, bytes calldata hookData)
        internal
        override
        returns (bytes4, int128)
    {
        // Optional: re-validate or be a no-op for demo
        (uint256 pollId, uint256 amountIn, uint256 minOut, address initiator) =
            abi.decode(hookData, (uint256, uint256, uint256, address));
        require(groupSwap.verifyExecution(pollId, amountIn, minOut, initiator), "GroupSwapHook: unauthorized post");
        return (BaseHook.afterSwap.selector, 0);
    }
}
