// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IUniswapV4Router04} from "hookmate/interfaces/router/IUniswapV4Router04.sol";
import {Sapphire} from "./libraries/Sapphire.sol";

interface IHookLike {
    function getHookPermissions() external pure returns (bytes memory);
}

/// @notice GroupSwap: Social Swap Polls / Group Trades
contract GroupSwap is ReentrancyGuard, Ownable {
    struct Poll {
        address creator;
        address tokenIn;
        address tokenOut;
        address depositToken; // same as tokenIn for simplicity
        uint256 targetAmount;
        uint256 totalDeposited;
        uint256 votesFor;
        uint256 votesAgainst;
        uint64 startTime;
        uint64 endTime;
        bool executed;
        uint16 maxSlippageBps; // e.g., 300 = 3%
        uint16 relayerFeeBps;  // for demo, we won't transfer fees out, but stored
        // optional Sapphire private voting
        bool isPrivate;
        uint8 sapphireAlg; // Sapphire.SigningAlg enum value
        bytes sapphirePublicKey; // compressed/secp or raw depending on alg
        // execution results
        uint256 amountInUsed;
        uint256 amountOutReceived;
    }

    struct PendingExec {
        uint256 amountIn;
        uint256 minOut;
        bool set;
    }

    event PollCreated(uint256 indexed pollId, address indexed creator, address tokenIn, address tokenOut, uint256 targetAmount, uint64 startTime, uint64 endTime, uint16 maxSlippageBps, uint16 relayerFeeBps);
    event PrivatePollCreated(uint256 indexed pollId, address indexed creator, address tokenIn, address tokenOut, uint256 targetAmount, uint64 startTime, uint64 endTime, uint16 maxSlippageBps, uint16 relayerFeeBps, uint8 sapphireAlg);
    event Deposited(uint256 indexed pollId, address indexed user, uint256 amount);
    event Voted(uint256 indexed pollId, address indexed user, bool support, uint256 weight);
    event VotedPrivate(uint256 indexed pollId, address indexed user, bool support, uint256 weight);
    event Executed(uint256 indexed pollId, uint256 amountIn, uint256 amountOut);
    event Claimed(uint256 indexed pollId, address indexed user, uint256 amountOut);
    event Refunded(uint256 indexed pollId, address indexed user, uint256 amount);

    IUniswapV4Router04 public immutable router;
    IHooks public hook; // the GroupSwapHook used in the PoolKey (settable once)

    // polls
    Poll[] public polls;
    mapping(uint256 => PendingExec) public pending; // params approved for hook

    // accounting per poll
    mapping(uint256 => mapping(address => uint256)) public deposits;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(uint256 => mapping(address => bool)) public voteSupport; // record latest vote
    mapping(uint256 => mapping(address => bool)) public claimed;
    mapping(uint256 => mapping(address => bool)) public refunded;

    constructor(IUniswapV4Router04 _router) Ownable(msg.sender) {
        router = _router;
    }

    function setHook(IHooks _hook) external onlyOwner {
        require(address(hook) == address(0), "hook set");
        require(address(_hook) != address(0), "bad hook");
        hook = _hook;
    }

    function createPoll(
        address tokenIn,
        address tokenOut,
        uint256 targetAmount,
        uint64 startTime,
        uint64 endTime,
        uint16 maxSlippageBps,
        uint16 relayerFeeBps
    ) external returns (uint256 pollId) {
        require(tokenIn != address(0) && tokenOut != address(0), "invalid tokens");
        require(startTime < endTime, "time window");
        require(maxSlippageBps <= 10_000, "slippage");
        pollId = polls.length;
        polls.push();
        Poll storage p = polls[pollId];
        p.creator = msg.sender;
        p.tokenIn = tokenIn;
        p.tokenOut = tokenOut;
        p.depositToken = tokenIn;
        p.targetAmount = targetAmount;
        p.totalDeposited = 0;
        p.votesFor = 0;
        p.votesAgainst = 0;
        p.startTime = startTime;
        p.endTime = endTime;
        p.executed = false;
        p.maxSlippageBps = maxSlippageBps;
        p.relayerFeeBps = relayerFeeBps;
        p.isPrivate = false;
        p.sapphireAlg = 0;
        p.sapphirePublicKey = "";
        p.amountInUsed = 0;
        p.amountOutReceived = 0;
        emit PollCreated(pollId, msg.sender, tokenIn, tokenOut, targetAmount, startTime, endTime, maxSlippageBps, relayerFeeBps);
    }

    // Private poll creation using Sapphire verification; expects Secp256k1PrehashedKeccak256 (enum value 4)
    function createPollPrivate(
        address tokenIn,
        address tokenOut,
        uint256 targetAmount,
        uint64 startTime,
        uint64 endTime,
        uint16 maxSlippageBps,
        uint16 relayerFeeBps,
        uint8 sapphireAlg,
        bytes calldata sapphirePublicKey
    ) external returns (uint256 pollId) {
        require(tokenIn != address(0) && tokenOut != address(0), "invalid tokens");
        require(startTime < endTime, "time window");
        require(maxSlippageBps <= 10_000, "slippage");
        // For demo, we support Secp256k1PrehashedKeccak256 path primarily (enum value 4)
        require(sapphireAlg == uint8(Sapphire.SigningAlg.Secp256k1PrehashedKeccak256), "alg");

        pollId = polls.length;
        polls.push();
        Poll storage p = polls[pollId];
        p.creator = msg.sender;
        p.tokenIn = tokenIn;
        p.tokenOut = tokenOut;
        p.depositToken = tokenIn;
        p.targetAmount = targetAmount;
        p.totalDeposited = 0;
        p.votesFor = 0;
        p.votesAgainst = 0;
        p.startTime = startTime;
        p.endTime = endTime;
        p.executed = false;
        p.maxSlippageBps = maxSlippageBps;
        p.relayerFeeBps = relayerFeeBps;
        p.isPrivate = true;
        p.sapphireAlg = sapphireAlg;
        p.sapphirePublicKey = sapphirePublicKey;
        p.amountInUsed = 0;
        p.amountOutReceived = 0;
        emit PrivatePollCreated(pollId, msg.sender, tokenIn, tokenOut, targetAmount, startTime, endTime, maxSlippageBps, relayerFeeBps, sapphireAlg);
    }

    function deposit(uint256 pollId, uint256 amount) external nonReentrant {
        Poll storage p = _poll(pollId);
        require(block.timestamp >= p.startTime && block.timestamp <= p.endTime, "not active");
        require(!p.executed, "executed");
        require(amount > 0, "amount");
        IERC20(p.depositToken).transferFrom(msg.sender, address(this), amount);
        deposits[pollId][msg.sender] += amount;
        p.totalDeposited += amount;
        emit Deposited(pollId, msg.sender, amount);
    }

    function vote(uint256 pollId, bool support) external {
        Poll storage p = _poll(pollId);
        require(!p.isPrivate, "private poll");
        require(block.timestamp <= p.endTime, "voting over");
        uint256 weight = deposits[pollId][msg.sender];
        require(weight > 0, "no deposit");

        // adjust tallies if re-voting
        if (hasVoted[pollId][msg.sender]) {
            if (voteSupport[pollId][msg.sender]) {
                p.votesFor -= weight;
            } else {
                p.votesAgainst -= weight;
            }
        }
        hasVoted[pollId][msg.sender] = true;
        voteSupport[pollId][msg.sender] = support;

        if (support) p.votesFor += weight; else p.votesAgainst += weight;

        emit Voted(pollId, msg.sender, support, weight);
    }

    // vote using Sapphire signature over keccak256(abi.encode(pollId, voter, support))
    function votePrivate(uint256 pollId, bool support, bytes calldata signature) external {
        Poll storage p = _poll(pollId);
        require(p.isPrivate, "not private");
        require(block.timestamp <= p.endTime, "voting over");
        uint256 weight = deposits[pollId][msg.sender];
        require(weight > 0, "no deposit");

        // Construct digest and verify signature
        bool ok = Sapphire.verify(
            Sapphire.SigningAlg(p.sapphireAlg),
            p.sapphirePublicKey,
            abi.encodePacked(keccak256(abi.encode(pollId, msg.sender, support))),
            "",
            signature
        );
        require(ok, "sapphire verify");

        // adjust tallies if re-voting
        if (hasVoted[pollId][msg.sender]) {
            if (voteSupport[pollId][msg.sender]) {
                p.votesFor -= weight;
            } else {
                p.votesAgainst -= weight;
            }
        }
        hasVoted[pollId][msg.sender] = true;
        voteSupport[pollId][msg.sender] = support;

        if (support) p.votesFor += weight; else p.votesAgainst += weight;

        emit VotedPrivate(pollId, msg.sender, support, weight);
    }

    function quorumReached(uint256 pollId) public view returns (bool) {
        Poll storage p = polls[pollId];
        if (p.totalDeposited == 0) return false;
        bool majority = p.votesFor >= p.totalDeposited / 2 + 1; // simple majority of deposits
        bool targetMet = p.totalDeposited >= p.targetAmount;
        return majority && targetMet;
    }

    function executePoll(uint256 pollId, uint256 amountIn, uint256 minOut, PoolKey calldata poolKey, bool zeroForOne) external nonReentrant {
        Poll storage p = _poll(pollId);
        require(block.timestamp > p.endTime, "too early");
        require(!p.executed, "already executed");
        require(quorumReached(pollId), "no quorum");
        require(amountIn > 0 && amountIn <= p.totalDeposited, "amountIn invalid");
        require(poolKey.hooks == hook, "hook mismatch");
        // Simple slippage policy for demo: require minOut >= amountIn * (1 - maxSlippage)
        uint256 minAllowed = amountIn * (10_000 - p.maxSlippageBps) / 10_000;
        require(minOut >= minAllowed, "minOut too low");

        // approve swap router to pull tokens
        IERC20(p.tokenIn).approve(address(router), amountIn);

        // set pending approval for hook to check
        pending[pollId] = PendingExec({amountIn: amountIn, minOut: minOut, set: true});

        bytes memory hookData = abi.encode(pollId, amountIn, minOut, address(this));

        // Execute swap via router
        // For demo we use swapExactTokensForTokens as in scripts
        router.swapExactTokensForTokens({
            amountIn: amountIn,
            amountOutMin: minOut,
            zeroForOne: zeroForOne,
            poolKey: poolKey,
            hookData: hookData,
            receiver: address(this),
            deadline: block.timestamp + 300
        });

        // After swap, we expect this contract to hold tokenOut
        uint256 outBal = IERC20(p.tokenOut).balanceOf(address(this));
        require(outBal > 0, "no out");

        p.executed = true;
        p.amountInUsed = amountIn;
        p.amountOutReceived = outBal;

        emit Executed(pollId, amountIn, outBal);
    }

    function verifyExecution(uint256 pollId, uint256 amountIn, uint256 minOut, address initiator) external view returns (bool) {
        if (msg.sender != address(hook)) return false; // only our hook queries should pass
        Poll storage p = polls[pollId];
        if (initiator != address(this)) return false;
        if (p.executed) return false;
        if (!(block.timestamp > p.endTime)) return false;
        if (!quorumReached(pollId)) return false;
        PendingExec storage pe = pending[pollId];
        if (!pe.set) return false;
        if (pe.amountIn != amountIn) return false;
        if (pe.minOut > minOut) return false; // require minOut >= approved minOut
        return true;
    }

    function claim(uint256 pollId) external nonReentrant {
        Poll storage p = _poll(pollId);
        require(p.executed, "not executed");
        require(!claimed[pollId][msg.sender], "claimed");
        uint256 userDep = deposits[pollId][msg.sender];
        require(userDep > 0, "no deposit");
        // Distribute proportionally to totalDeposited so that claims sum to total output
        uint256 amount = p.amountOutReceived * userDep / p.totalDeposited;
        claimed[pollId][msg.sender] = true;
        IERC20(p.tokenOut).transfer(msg.sender, amount);
        emit Claimed(pollId, msg.sender, amount);
    }

    function refundIfFailed(uint256 pollId) external nonReentrant {
        Poll storage p = _poll(pollId);
        require(block.timestamp > p.endTime, "not ended");
        require(!p.executed, "executed");
        require(!refunded[pollId][msg.sender], "refunded");
        uint256 amount = deposits[pollId][msg.sender];
        require(amount > 0, "no deposit");
        refunded[pollId][msg.sender] = true;
        IERC20(p.depositToken).transfer(msg.sender, amount);
        emit Refunded(pollId, msg.sender, amount);
    }

    function _poll(uint256 pollId) internal view returns (Poll storage) {
        require(pollId < polls.length, "bad id");
        return polls[pollId];
    }
}
