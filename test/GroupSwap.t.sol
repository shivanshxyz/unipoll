// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {LiquidityAmounts} from "@uniswap/v4-core/test/utils/LiquidityAmounts.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {Constants} from "@uniswap/v4-core/test/utils/Constants.sol";

import {IPositionManager} from "@uniswap/v4-periphery/src/interfaces/IPositionManager.sol";

import {Deployers} from "./utils/Deployers.sol";
import {EasyPosm} from "./utils/libraries/EasyPosm.sol";

import {GroupSwap} from "../src/GroupSwap.sol";
import {GroupSwapHook} from "../src/GroupSwapHook.sol";
import {MockERC20} from "../src/MockERC20.sol";

contract GroupSwapTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using EasyPosm for IPositionManager;

    GroupSwap group;
    GroupSwapHook hook;

    MockERC20 tokenIn;
    MockERC20 tokenOut;

    Currency currency0;
    Currency currency1;

    PoolKey poolKey;
    PoolId poolId;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    uint256 tokenId;
    int24 tickLower;
    int24 tickUpper;

    function setUp() public {
        console2.log(unicode"🧪 Setup: Deploy base artifacts (Permit2, PoolManager, PositionManager, Router)");
        // Deploy base artifacts (permit2, poolManager, positionManager, router)
        deployArtifacts();

        // Deploy test tokens
        console2.log(unicode"🪙 Minting test tokens for TokenIn and TokenOut");
        tokenIn = new MockERC20("TokenIn", "TIN");
        tokenOut = new MockERC20("TokenOut", "TOUT");
        tokenIn.mint(address(this), 10_000 ether);
        tokenOut.mint(address(this), 10_000 ether);

        // Distribute tokens to users
        tokenIn.transfer(alice, 1_000 ether);
        tokenIn.transfer(bob, 1_000 ether);

        // Approvals for router and permit2 (not strictly necessary for deposit flow but for liquidity)
        tokenIn.approve(address(permit2), type(uint256).max);
        tokenOut.approve(address(permit2), type(uint256).max);
        permit2.approve(address(tokenIn), address(positionManager), type(uint160).max, type(uint48).max);
        permit2.approve(address(tokenOut), address(positionManager), type(uint160).max, type(uint48).max);

        // Deploy GroupSwap with router
        console2.log(unicode"🚀 Deploying GroupSwap and GroupSwapHook with BEFORE/AFTER_SWAP flags");
        group = new GroupSwap(swapRouter);

        // Deploy hook at an address with flags BEFORE/AFTER_SWAP
        address flags = address(uint160((Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG)) ^ (0x7777 << 144));
        bytes memory constructorArgs = abi.encode(poolManager, address(group));
        deployCodeTo("GroupSwapHook.sol:GroupSwapHook", constructorArgs, flags);
        hook = GroupSwapHook(flags);

        // Wire the hook into GroupSwap
        group.setHook(IHooks(hook));

        // Create pool
        console2.log(unicode"🏊 Creating pool and initializing at price 1:1, then adding full-range liquidity");
        (currency0, currency1) = _currOrder(address(tokenIn), address(tokenOut));
        poolKey = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(hook)
        });
        poolId = poolKey.toId();
        poolManager.initialize(poolKey, Constants.SQRT_PRICE_1_1);

        // Provide liquidity full range
        tickLower = TickMath.minUsableTick(poolKey.tickSpacing);
        tickUpper = TickMath.maxUsableTick(poolKey.tickSpacing);

        uint128 liq = 1_000e18;
        (uint256 amt0, uint256 amt1) = LiquidityAmounts.getAmountsForLiquidity(
            Constants.SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            liq
        );

        // Approvals for adding liquidity
        console2.log(unicode"✅ Approving Permit2 + PositionManager and minting liquidity");
        tokenIn.approve(address(permit2), type(uint256).max);
        tokenOut.approve(address(permit2), type(uint256).max);
        permit2.approve(address(tokenIn), address(positionManager), type(uint160).max, type(uint48).max);
        permit2.approve(address(tokenOut), address(positionManager), type(uint160).max, type(uint48).max);

        positionManager.mint(
            poolKey,
            tickLower,
            tickUpper,
            liq,
            amt0 + 1,
            amt1 + 1,
            address(this),
            block.timestamp,
            Constants.ZERO_BYTES
        );
    }

    function _currOrder(address a, address b) internal pure returns (Currency, Currency) {
        if (a < b) return (Currency.wrap(a), Currency.wrap(b));
        return (Currency.wrap(b), Currency.wrap(a));
    }

    function test_full_flow_group_swap() public {
        console2.log(unicode"📋 Creating a public poll (non-private)");
        // Create poll
        uint64 start = uint64(block.timestamp);
        uint64 end = uint64(block.timestamp + 1 hours);
        uint256 target = 100 ether;
        uint16 maxSlip = 500; // 5%
        uint16 feeBps = 0;
        uint256 pollId = group.createPoll(address(tokenIn), address(tokenOut), target, start, end, maxSlip, feeBps);

        // Deposits
        console2.log(unicode"👥 Alice deposits 60 TIN and votes YES");
        vm.startPrank(alice);
        tokenIn.approve(address(group), type(uint256).max);
        group.deposit(pollId, 60 ether);
        group.vote(pollId, true);
        vm.stopPrank();

        console2.log(unicode"👥 Bob deposits 60 TIN and votes YES");
        vm.startPrank(bob);
        tokenIn.approve(address(group), type(uint256).max);
        group.deposit(pollId, 60 ether);
        group.vote(pollId, true);
        vm.stopPrank();

        // Move time forward beyond end
        console2.log(unicode"⏩ Fast-forwarding time beyond poll end");
        vm.warp(end + 1);

        // Execute
        console2.log(unicode"🔁 Executing group swap via router (hook authorizes) with amountIn=10e18 and 5% slippage");
        bool zeroForOne = (Currency.unwrap(currency0) == address(tokenIn));
        uint256 amountIn = 10 ether; // smaller amount to satisfy minOut given pool liquidity
        uint256 minOut = amountIn * (10_000 - maxSlip) / 10_000; // Respect slippage bound
        group.executePoll(pollId, amountIn, minOut, poolKey, zeroForOne);

        // Users claim proportionally
        console2.log(unicode"📤 Users claim proportional TokenOut amounts");
        uint256 outBal = tokenOut.balanceOf(address(group));
        assertGt(outBal, 0);

        vm.prank(alice);
        group.claim(pollId);
        vm.prank(bob);
        group.claim(pollId);

        // Validate distributions sum to outBal
        console2.log(unicode"🧮 Validating claim distribution sums to pool output");
        uint256 aliceOut = tokenOut.balanceOf(alice);
        uint256 bobOut = tokenOut.balanceOf(bob);
        assertEq(aliceOut + bobOut, outBal);
    }

    function test_negative_execute_too_early_reverts() public {
        uint64 start = uint64(block.timestamp);
        uint64 end = uint64(block.timestamp + 1 hours);
        uint256 pollId = group.createPoll(address(tokenIn), address(tokenOut), 10 ether, start, end, 500, 0);

        vm.startPrank(alice);
        tokenIn.approve(address(group), type(uint256).max);
        group.deposit(pollId, 10 ether);
        group.vote(pollId, true);
        vm.stopPrank();

        bool zeroForOne = (Currency.unwrap(currency0) == address(tokenIn));
        console2.log(unicode"❌ Expect revert: executing before endTime");
        vm.expectRevert("too early");
        group.executePoll(pollId, 10 ether, 1, poolKey, zeroForOne);
    }

    function test_negative_no_quorum_reverts() public {
        uint64 start = uint64(block.timestamp);
        uint64 end = uint64(block.timestamp + 1 hours);
        uint256 pollId = group.createPoll(address(tokenIn), address(tokenOut), 100 ether, start, end, 500, 0);

        vm.prank(alice);
        tokenIn.approve(address(group), type(uint256).max);
        vm.prank(alice);
        group.deposit(pollId, 10 ether);
        // no votes or insufficient target

        vm.warp(end + 1);
        bool zeroForOne = (Currency.unwrap(currency0) == address(tokenIn));
        console2.log(unicode"❌ Expect revert: quorum not reached");
        vm.expectRevert("no quorum");
        group.executePoll(pollId, 10 ether, 1, poolKey, zeroForOne);
    }

    function test_negative_slippage_reverts() public {
        uint64 start = uint64(block.timestamp);
        uint64 end = uint64(block.timestamp + 1 hours);
        uint16 maxSlip = 500;
        uint256 pollId = group.createPoll(address(tokenIn), address(tokenOut), 10 ether, start, end, maxSlip, 0);

        vm.startPrank(alice);
        tokenIn.approve(address(group), type(uint256).max);
        group.deposit(pollId, 10 ether);
        group.vote(pollId, true);
        vm.stopPrank();

        vm.warp(end + 1);
        bool zeroForOne = (Currency.unwrap(currency0) == address(tokenIn));
        uint256 amountIn = 10 ether;
        uint256 minOut = amountIn * (10_000 - maxSlip) / 10_000 - 1; // too low
        console2.log(unicode"❌ Expect revert: minOut below allowed slippage");
        vm.expectRevert("minOut too low");
        group.executePoll(pollId, amountIn, minOut, poolKey, zeroForOne);
    }

    function test_negative_non_group_swap_caller_reverts_via_hook() public {
        // Create poll satisfied but attempt to bypass GroupSwap
        uint64 start = uint64(block.timestamp);
        uint64 end = uint64(block.timestamp + 1 hours);
        uint16 maxSlip = 500;
        uint256 pollId = group.createPoll(address(tokenIn), address(tokenOut), 10 ether, start, end, maxSlip, 0);

        vm.startPrank(alice);
        tokenIn.approve(address(group), type(uint256).max);
        group.deposit(pollId, 10 ether);
        group.vote(pollId, true);
        vm.stopPrank();

        vm.warp(end + 1);

        // Try to call router directly from this contract
        bool zeroForOne = (Currency.unwrap(currency0) == address(tokenIn));
        uint256 amountIn = 10 ether;
        uint256 minOut = amountIn * (10_000 - maxSlip) / 10_000;

        // need balances & approvals
        tokenIn.approve(address(swapRouter), type(uint256).max);

        bytes memory hookData = abi.encode(pollId, amountIn, minOut, address(this));

        console2.log(unicode"🛡️ Hook authorization test: direct router call should revert");
        vm.expectRevert(); // Hook should revert due to verifyExecution false
        swapRouter.swapExactTokensForTokens({
            amountIn: amountIn,
            amountOutMin: minOut,
            zeroForOne: zeroForOne,
            poolKey: poolKey,
            hookData: hookData,
            receiver: address(this),
            deadline: block.timestamp + 60
        });
    }
}
