// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {LiquidityAmounts} from "@uniswap/v4-core/test/utils/LiquidityAmounts.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {Constants} from "@uniswap/v4-core/test/utils/Constants.sol";

import {IPositionManager} from "@uniswap/v4-periphery/src/interfaces/IPositionManager.sol";

import {Deployers} from "./utils/Deployers.sol";
import {EasyPosm} from "./utils/libraries/EasyPosm.sol";

import {GroupSwap} from "../src/GroupSwap.sol";
import {GroupSwapHook} from "../src/GroupSwapHook.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {Sapphire} from "../src/libraries/Sapphire.sol";

contract GroupSwapPrivateTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using EasyPosm for IPositionManager;

    // Sapphire chain IDs (known)
    uint256 constant SAPPHIRE_MAINNET = 23294;
    uint256 constant SAPPHIRE_TESTNET = 23295;

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

    int24 tickLower;
    int24 tickUpper;

    function setUp() public {
        console2.log(unicode"🧪 Private Test Setup: Deploy artifacts (Permit2, PoolManager, PositionManager, Router)");
        // Only meaningful on Sapphire networks; otherwise we keep the test a no-op.
        // We still deploy artifacts to avoid unexpected reverts in local.
        deployArtifacts();

        console2.log(unicode"🪙 Minting and distributing TokenIn/TokenOut");
        tokenIn = new MockERC20("TokenIn", "TIN");
        tokenOut = new MockERC20("TokenOut", "TOUT");
        tokenIn.mint(address(this), 10_000 ether);
        tokenOut.mint(address(this), 10_000 ether);

        tokenIn.transfer(alice, 1_000 ether);
        tokenIn.transfer(bob, 1_000 ether);

        console2.log(unicode"✅ Approving Permit2 + PositionManager");
        tokenIn.approve(address(permit2), type(uint256).max);
        tokenOut.approve(address(permit2), type(uint256).max);
        permit2.approve(address(tokenIn), address(positionManager), type(uint160).max, type(uint48).max);
        permit2.approve(address(tokenOut), address(positionManager), type(uint160).max, type(uint48).max);

        console2.log(unicode"🚀 Deploying GroupSwap and GroupSwapHook (private voting demo)");
        group = new GroupSwap(swapRouter);

        // Hook flags for before/after swap
        address flags = address(uint160((Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG)) ^ (0x7777 << 144));
        bytes memory constructorArgs = abi.encode(poolManager, address(group));
        deployCodeTo("GroupSwapHook.sol:GroupSwapHook", constructorArgs, flags);
        hook = GroupSwapHook(flags);

        group.setHook(IHooks(hook));

        console2.log(unicode"🏊 Creating pool with hook and adding full-range liquidity");
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

        tickLower = TickMath.minUsableTick(poolKey.tickSpacing);
        tickUpper = TickMath.maxUsableTick(poolKey.tickSpacing);

        uint128 liq = 1_000e18;
        (uint256 amt0, uint256 amt1) = LiquidityAmounts.getAmountsForLiquidity(
            Constants.SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            liq
        );

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

    function test_private_poll_flow_on_sapphire() public {
        // Skip unless running on Sapphire networks (precompiles available)
        if (block.chainid != SAPPHIRE_MAINNET && block.chainid != SAPPHIRE_TESTNET) {
            console2.log(unicode"⏭️ Skipping private poll test: not on Sapphire network");
            return; // no-op on non-Sapphire chains
        }

        // Generate a demo signing keypair on-chain via Sapphire
        console2.log(unicode"🔐 Generating Sapphire signing keypair (Secp256k1PrehashedKeccak256)");
        (bytes memory pubKey, bytes memory secKey) = Sapphire.generateSigningKeyPair(
            Sapphire.SigningAlg.Secp256k1PrehashedKeccak256, Sapphire.randomBytes(32, "groupswap")
        );

        uint64 start = uint64(block.timestamp);
        uint64 end = uint64(block.timestamp + 1 hours);
        uint256 target = 20 ether;
        uint16 maxSlip = 500; // 5%

        console2.log(unicode"📋 Creating private poll with Sapphire public key");
        uint256 pollId = group.createPollPrivate(
            address(tokenIn),
            address(tokenOut),
            target,
            start,
            end,
            maxSlip,
            0,
            uint8(Sapphire.SigningAlg.Secp256k1PrehashedKeccak256),
            pubKey
        );

        // Deposits
        console2.log(unicode"👥 Alice and Bob deposit to private poll");
        vm.startPrank(alice);
        tokenIn.approve(address(group), type(uint256).max);
        group.deposit(pollId, 15 ether);
        vm.stopPrank();

        vm.startPrank(bob);
        tokenIn.approve(address(group), type(uint256).max);
        group.deposit(pollId, 15 ether);
        vm.stopPrank();

        // Private votes (signed by Sapphire keypair)
        console2.log(unicode"🗳️ Private voting with Sapphire signatures (YES/YES)");
        // Alice votes yes
        bytes memory digestAlice = abi.encodePacked(keccak256(abi.encode(pollId, alice, true)));
        bytes memory sigAlice = Sapphire.sign(
            Sapphire.SigningAlg.Secp256k1PrehashedKeccak256,
            secKey,
            digestAlice,
            ""
        );
        vm.prank(alice);
        group.votePrivate(pollId, true, sigAlice);

        // Bob votes yes
        bytes memory digestBob = abi.encodePacked(keccak256(abi.encode(pollId, bob, true)));
        bytes memory sigBob = Sapphire.sign(
            Sapphire.SigningAlg.Secp256k1PrehashedKeccak256,
            secKey,
            digestBob,
            ""
        );
        vm.prank(bob);
        group.votePrivate(pollId, true, sigBob);

        // Move time forward
        console2.log(unicode"⏩ Fast-forwarding time beyond private poll end");
        vm.warp(end + 1);

        bool zeroForOne = (Currency.unwrap(currency0) == address(tokenIn));
        uint256 amountIn = 10 ether;
        uint256 minOut = amountIn * (10_000 - maxSlip) / 10_000;
        console2.log(unicode"🔁 Executing group swap for private poll");
        group.executePoll(pollId, amountIn, minOut, poolKey, zeroForOne);

        // Claims
        console2.log(unicode"📤 Claiming TokenOut for Alice & Bob");
        vm.prank(alice);
        group.claim(pollId);
        vm.prank(bob);
        group.claim(pollId);

        // Success condition: both should have received some tokenOut
        console2.log(unicode"✅ Private poll flow completed with claims");
        assertGt(tokenOut.balanceOf(alice), 0);
        assertGt(tokenOut.balanceOf(bob), 0);
    }
}
