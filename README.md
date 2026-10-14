# MilestoneEscrow — Consensus-Gated Milestone Escrow with Live Payout

> **A funder deposits GEN for a milestone; the worker proves delivery with a URL; validators independently fetch the evidence and score it under consensus. A verified verdict pays the worker via a live GEN transfer; a rejected verdict, a cancellation, or an expired deadline refunds the funder.**
>
> This contract has **real custody**: it receives GEN (payable), tracks total locked liability in storage, and settles escrows with live `EthSend` value transfers — consensus decides the payout direction automatically in the settling transaction.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Equivalence](https://img.shields.io/badge/Equivalence%20Principle-OK-16a34a?style=for-the-badge)](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)
[![Tests](https://img.shields.io/badge/tests-25%20passed-16a34a?style=for-the-badge)](https://github.com/)

---

## Table of Contents

- [How it works](#how-it-works)
- [Consensus design](#consensus-design)
- [Difference from existing contracts](#difference-from-existing-contracts)
- [Reusable patterns](#reusable-patterns)
- [Security & audit](#security--audit)
- [Local lint & test](#local-lint--test)
- [Deployed contract (proof on explorer)](#deployed-contract-proof-on-explorer)
- [Extension ideas](#extension-ideas)

---

## How it works

1. The funder creates an escrow for a **specific worker**: milestone text, deadline, and a GEN deposit (payable).
2. Before the deadline, the worker submits proof of delivery (URL + description), signed with their wallet (EIP-191).
3. Anyone triggers settlement (`verify_escrow`).
4. Under consensus, validators independently fetch the evidence from the URL and score it against the milestone via LLM.
5. The verdict settles the escrow **in the same transaction**:
   - score ≥ 60 → `released` — GEN is transferred to the worker;
   - score < 60 → `refunded` — GEN is returned to the funder.
6. Alternate paths: the funder can cancel while the escrow is still `open` (refund), or reclaim after the deadline passes (refund).

Escrow id format: `{funder_hex}:{seq}` (monotonic per contract).

---

## Consensus design

MilestoneEscrow uses `run_nondet_unsafe` with the Equivalence Principle:
- **Leader**: fetches the actual evidence from the proof URL via `gl.nondet.web.get()` (with SSRF/DNS-rebinding defense), then scores the fetched content + description against the milestone via LLM.
- **Validator**: independently fetches the same URL and re-scores, then compares decision fields: `verified` must match exactly, `proof_score` within an explicit ±10 tolerance (LLM scores vary across independent runs — exact equality causes `MAJORITY_DISAGREE`).
- Both leader and validators assess retrieved evidence — never just the URL string or description.
- Error classification: `[EXPECTED]` for deterministic errors (exact match), `[EXTERNAL]` for 4xx/blocked (exact match), `[TRANSIENT]` for 5xx/network (agree if both), `[LLM]` for LLM errors (always disagree, force rotation).
- LLM consensus disagreement is expected with real models; `verify_escrow` can be retried and the escrow stays `proof_submitted` until agreement (state rolls back on DISAGREE).

Liability accounting: `locked_total` (storage) tracks the sum of all open escrow amounts. Settlement and refunds decrement it before the live transfer. `self.balance` is deliberately not used for accounting (it is unreliable outside on-chain execution; the same pattern as BountyBoard/SwapShield).

---

## Difference from existing contracts

| Contract | Model | Custody | Settlement |
|---|---|---|---|
| **BountyBoard** | Open marketplace — anyone can attempt a posted bounty; AST-sandbox ground truth; worker **claims** the reward in a separate step | Holds GEN | Claim step after approval |
| **EscrowMediator** | Buyer/seller/mediator **dispute resolution** — funds are only *represented* as a record | **Non-custodial** | Mediator decides after dispute |
| **SwapShield** | OTC **swap** between two assets with dual-signature consent | Holds GEN deposits | Both parties withdraw after settlement |
| **MilestoneEscrow** | **Directed bilateral work contract** — funder names one specific worker; one-shot proof; **automatic settlement pays out in the same consensus transaction** | Holds GEN (payable) | Consensus verdict → live `EthSend` payout, no claim step |

---

## Reusable patterns

- **Real custody with consensus-gated live payout**: payable intake, `locked_total` liability ledger, `_pay_out` via `_EOA(to).emit_transfer(value=..., on="finalized")` with `Address()` coercion (client-supplied addresses arrive as plain strings — without coercion the executor rejects with `SystemError: 2: inval`).
- **EIP-191 signature verification**: `_signer_of()` + `_ecrecover()` — pure-Python secp256k1 ecrecover binding proof submission to the worker's wallet.
- **Directed escrow relationship model**: funder names the worker at creation; only that worker can submit proof; funder cannot be the worker.
- **Score tolerance in consensus**: exact decision-bit match + explicit numeric tolerance for LLM score variance.
- **Proof-of-delivery scoring**: LLM evaluation of fetched evidence vs. milestone in the consensus loop.
- **SSRF/DNS-rebinding defense**: full stack (see Security) — the same proven policy as PledgeVerify.

---

## Security & audit

- **Signature verification**: proof submission requires an EIP-191 signature over `MilestoneEscrow:proof:{escrow_id}:{url}:{description[:50]}`, verified on-chain; the recovered signer must equal the submitting worker.
- **Access control**: only the named worker can submit proof; only the funder can cancel or reclaim; settlement is open to anyone (it can only follow the consensus verdict).
- **State machine**: `open → proof_submitted → released|refunded`; cancel/reclaim only from `open`; no double settlement; no proof after deadline.
- **SSRF policy**: proof URLs parsed with `urllib.parse`, host-checked with `ipaddress` — blocks private/loopback/link-local/reserved/multicast IPv4+IPv6 (incl. CGNAT), decimal/hex/octal numeric IP literals, userinfo, control characters, backslashes, and `.local`/`.internal`/`.localhost`/`.nip.io`/`.sslip.io`/`metadata.google` hosts.
- **DNS resolution before fetch**: every hop's hostname resolved via DNS-over-HTTPS (`dns.google/resolve`, A + AAAA) inside the consensus loop; any private/loopback/resolved address blocks the fetch (`[EXTERNAL]`) before a request is sent — closing DNS-rebinding. NXDOMAIN → `[EXTERNAL]`; resolver outage → `[TRANSIENT]`.
- **Redirect validation**: at most 5 redirects, relative `Location` resolution, URL policy and hostname re-resolution on every hop.
- **Liability accounting**: `locked_total` decremented before every payout; multiple concurrent escrows tracked independently.
- **Input validation**: milestone/description length limits, deadline must be in the future, deposit must be positive, funder ≠ worker, payout must be positive.

---

## Local lint & test

```bash
# Run tests
pytest tests/ -v

# Run linter
genvm-lint check contracts/milestone_escrow.py
```

25 GenVM direct-mode tests pass. Lint passes. E2E test passes on studionet (create_escrow → submit_proof → verify_escrow under real LLM+web consensus → MAJORITY_AGREE → `released` score 95 → live GEN payout verified at worker address; liability accounting exact; leftover escrows settle cleanly). Deployed to studionet.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0xED3E9616582ffb30f47F75866ba97Caf71a4540c`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0xe47b95cc5accd2b855647c9a2c6147a48ee3af5c5e1e3b0f6ec1354b1998970e`
**Status:** Deployed and tested on studionet. Full E2E passes (create → deposit → proof → consensus settlement → live GEN transfer to worker). 25/25 direct-mode tests pass. All functions operational: create_escrow, submit_proof, verify_escrow, cancel_escrow, reclaim_expired, views.

---

## Extension ideas

- Multi-worker milestone chains (sequenced milestones releasing tranches automatically)
- Partial delivery scoring (proportional payout instead of binary release/refund)
- Arbiter role for post-settlement disputes with additional evidence rounds
- Integration with SkillRegistry / BountyBoard for worker reputation-weighted scoring
