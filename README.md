# Unipoll

## What it does
- GroupSwap enables social group trades on Uniswap v4.
- Users pool ERC20 deposits, vote (weighted by deposit), and execute a collective swap when quorum and end time conditions are met.
- A Uniswap v4 hook enforces that only GroupSwap-approved swaps can execute.
- Optional Oasis Sapphire integration adds private voting with signature verification via Sapphire precompiles.

## The problem it solves
- Coordinating group trades is hard: scattered approvals, unclear thresholds, and trust issues.
- GroupSwap provides a transparent, on-chain governance flow for a one-shot trade:
    - Clear proposal window and quorum.
    - Weighted voting by capital committed.
    - Enforcement via a hook that prevents unauthorized swaps.
- With Sapphire, sensitive vote choices can be kept private while still verifiable on-chain.

## Challenges I ran into
- Uniswap v4 hooks integration
- stack too deep errors

## Technologies I used
Foundry, Solidity, Oasis Sapphire, Uniswap Hooks
- Uniswap Hooks for swap execution post quorum
- Oasis Sapphire for private voting

## How we built it
- Contracts (in src/):
    - GroupSwap.sol:
        - Poll lifecycle: createPoll, deposit, vote, createPollPrivate, votePrivate, executePoll, claim, refundIfFailed, quorumReached, verifyExecution.
        - Hook binding via setHook(IHooks).
        - Slippage guard and pending-execution parameters for the hook.

    - GroupSwapHook.sol
        - beforeSwap and afterSwap validation.
        - Ensures only swaps approved by GroupSwap.verifyExecution proceed.

    - libraries/Sapphire.sol
        - Wraps Sapphire precompiles for verify and sign.

## What's next for
UI dev, GTM
