# MilestoneEscrow — Consensus-Gated Milestone Escrow with Live Payout

> **A funder deposits GEN for a milestone; the worker proves delivery with a URL; validators independently fetch the evidence and score it under consensus. A verified verdict pays the worker via a live GEN transfer; a rejected verdict, a cancellation, or an expired deadline refunds the funder.**
>
> This contract has **real custody**: it receives GEN (payable), tracks total locked liability in storage, and settles escrows with live `EthSend` value transfers — consensus decides the payout direction automatically in the settling transaction.

[![GenLayer](https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer)](https://genlayer.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Equivalence](https://img.shields.io/badge/Equivalence%20Principle-OK-16a34a?style=for-the-badge)](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)
[![Tests](https://img.shields.io/badge/tests-38%20passed-16a34a?style=for-the-badge)](https://github.com/)

---

## Table of Contents

- [How it works](#how-it-works)
- [Consensus design](#consensus-design)
- [Steward review round 2 — the two fixes](#steward-review-round-2--the-two-fixes)
- [Difference from existing contracts](#difference-from-existing-contracts)
- [Reusable patterns](#reusable-patterns)
- [Security & audit](#security--audit)
- [Local lint & test](#local-lint--test)
- [Deployed contract (proof on explorer)](#deployed-contract-proof-on-explorer)
- [Extension ideas](#extension-ideas)

---

## How it works

1. The funder creates an escrow for a **specific worker**: milestone text, deadline, and a GEN deposit (payable).
2. Before the deadline, the worker submits proof of delivery (URL + description) on an allowlisted host, signed with their wallet (EIP-191).
3. Anyone triggers settlement (`verify_escrow`).
4. Under consensus, validators independently fetch the evidence from the URL and score it against the milestone via LLM.
5. The verdict settles the escrow **in the same transaction**:
   - score ≥ 60 → `released` — GEN is transferred to the worker;
   - score < 60 → `refunded` — GEN is returned to the funder.
6. Alternate paths: the funder can cancel while the escrow is still `open` (refund), reclaim after the deadline passes (refund, from **any** unsettled state), or refund immediately if consensus recorded a permanent proof-fetch failure.

Escrow id format: `{funder_hex}:{seq}` (monotonic per contract).

### State machine

```
              create_escrow (payable)
                      |
                      v
                    open  ------------------- cancel_escrow (funder) ------+
                      |                                                      |
        submit_proof  |                                                      |
                      v                                                      |
            proof_submitted                                                 |
                |        |                                                  |
   verify_escrow|        | verify_escrow (permanent fetch failure recorded)|
                |        v                                                  |
                |   fetch_failed -- refund_failed_escrow (funder) ---------+--> refunded
                |        |                                                  ^
                |        | reclaim_expired (funder, after deadline) ---------+
                v
        released (GEN to worker)  /  refunded (GEN to funder)
```

Every funded escrow has a terminal path: `open`/`proof_submitted`/`fetch_failed` can all reach `refunded`.

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

## Steward review round 2 — the two fixes

### 1. A funded escrow can no longer be stranded

**Problem**: `reclaim_expired` only accepted the `open` status. An escrow whose proof had been submitted but could never be verified (the evidence URL is gone) had **no** recovery path — the deposit was locked forever.

**Fix**:
- `verify_escrow` no longer reverts on a **permanent** proof-fetch failure. When the validators agree on a permanent error (`[EXTERNAL]` / `[EXPECTED]`), the contract records the escrow as `fetch_failed` together with `failure_reason`. Transient failures (5xx, network, LLM) still revert, so they stay retryable.
- `refund_failed_escrow` — funder-only, refunds a `fetch_failed` escrow immediately (no need to wait for the deadline).
- `reclaim_expired` now accepts **any unsettled state** (`open`, `proof_submitted`, `fetch_failed`) once the deadline has passed.
- The worker may replace a broken proof: `submit_proof` is accepted again from `fetch_failed` (the failed proof is overwritten and the failure reason cleared).

### 2. The fetch actually targets the checked destination

**Problem**: the DoH safety check resolved the hostname and validated the addresses, but `web.get(url)` then resolved the hostname **again** on its own — a classic TOCTOU window in which a submitter-controlled domain could be rebound to the validator's internal addresses.

**Fix — trusted fetch path**: proof URLs are restricted to an allowlist of domains whose DNS zone the proof submitter does not control (`example.com`, `github.com`, `githubusercontent.com`, `ipfs.io`, `dweb.link`, `arweave.net`, `wikipedia.org`, `iana.org`, plus their subdomains). The validator's own resolution can then only land on public, submitter-independent addresses. The allowlist is enforced twice: at submission time (`submit_proof`, so the worker gets immediate feedback) and on every fetch hop (including redirect targets).

**Why not IP pinning?** Pinning the connection to the validated address would be the strongest form, but it is impossible on-chain: the validator's URL validator rejects IP literals. Measured on studionet with the probe in `scripts/probe_fetch.py` (`scripts/probe_fetch_result.json`):

| variant | result |
|---|---|
| `https://example.com/` (baseline) | 200, 577 bytes |
| `https://93.184.216.34/…` + `Host: example.com` | `TLD_FORBIDDEN` |
| `http://93.184.216.34/…` + `Host: example.com` | `TLD_FORBIDDEN` |
| `https://93.184.216.34/…` (no Host header) | `TLD_FORBIDDEN` |

So the allowlist is the equivalent safe path. As defence in depth, every hop **re-resolves after the fetch** and requires the address set to be unchanged and still public (`[EXTERNAL] dns changed during fetch`) — a rebinding that happens inside the fetch window is detected and the content is discarded instead of being scored.

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
- **Access control**: only the named worker can submit proof; only the funder can cancel, reclaim or refund a failed escrow; settlement is open to anyone (it can only follow the consensus verdict).
- **State machine**: `open → proof_submitted → released|refunded`, plus `fetch_failed` (permanent fetch failure) which can only reach `refunded`; cancel/reclaim only from unsettled states; no double settlement; no proof after deadline.
- **No stranded funds**: every funded escrow can reach a terminal state — verified by consensus (release/refund), by the worker replacing a broken proof, by `refund_failed_escrow` after a recorded permanent fetch failure, or by `reclaim_expired` after the deadline.
- **Trusted fetch path**: proof URLs (and every redirect hop) must be on the operator-controlled allowlist — the submitter cannot control the DNS of an allowlisted domain, so the validator's own resolution cannot be pointed at internal infrastructure. Enforced at submission and at fetch time.
- **SSRF policy**: proof URLs are parsed with `urllib.parse` and host-checked with `ipaddress` — blocks private/loopback/link-local/reserved/multicast IPv4+IPv6 (incl. CGNAT), decimal/hex/octal numeric IP literals, userinfo, control characters, backslashes, and `.local`/`.internal`/`.localhost`/`.nip.io`/`.sslip.io`/`metadata.google` hosts.
- **DNS resolution before fetch**: every hop's hostname is resolved via DNS-over-HTTPS (`dns.google/resolve`, A + AAAA) inside the consensus loop; if any resolved address is private/loopback/link-local/reserved, the fetch is rejected (`[EXTERNAL] resolved address is blocked`) before any request is sent to it. NXDOMAIN raises `[EXTERNAL] host did not resolve`; resolver outages raise `[TRANSIENT]`.
- **Post-fetch DNS stability**: every hop is re-resolved after the fetch; the address set must be unchanged (non-empty intersection) and still public, otherwise the content is rejected (`[EXTERNAL] dns changed during fetch`).
- **Redirect validation**: `_fetch_proof_evidence` follows at most 5 redirects, resolving relative `Location` headers, re-validating the URL policy, re-checking the allowlist and re-resolving the hostname of every hop.
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

38 GenVM direct-mode tests pass (25 lifecycle/consensus + 13 covering the steward round 2 fixes: allowlist enforcement, allowlisted subdomains, permanent failure recorded, `refund_failed_escrow` incl. access control, deadline reclaim from `proof_submitted` and `fetch_failed`, proof replacement, transient failure staying retryable, DNS change during fetch, redirect to an untrusted host, settled escrow not reclaimable). Lint passes.

E2E on studionet (script `scripts/e2e-test.cjs`, `scripts/e2e-reclaim.cjs`, `scripts/audit-v2.cjs`) against the deployed address below — every escrow created against this deployment has been settled, `locked_total` is **0**:

| escrow | path exercised | final status | live GEN transfer |
|---|---|---|---|
| `:0` | consensus release (score 95) | `released` | paid to the worker ✓ |
| `:1` | proof URL permanently 404 → `fetch_failed` → `refund_failed_escrow` | `refunded` | refunded to the funder ✓ |
| `:3` | consensus verdict below threshold (score 46) | `refunded` | refunded to the funder ✓ |
| `:4` | consensus release (score 95) | `released` | paid to the worker ✓ |
| `:5` | proof URL permanently 404 → `fetch_failed` → `refund_failed_escrow` | `refunded` | refunded to the funder ✓ |
| `:6` | proof submitted, deadline passed → `reclaim_expired` | `refunded` | refunded to the funder ✓ |

Consensus notes: `verify_escrow` may return MAJORITY_DISAGREE on a given attempt (LLM score variance) — the escrow stays `proof_submitted` and the call is simply retried; agreement was reached on attempt 1–3 in these runs. `failure_reason` recorded on-chain for the permanent failures: `[EXTERNAL] URL returned 404`.

---

## Deployed contract (proof on explorer)

[![Explore](https://img.shields.io/badge/Explore-Studionet-6366f1?style=for-the-badge)](https://genlayer-explorer.vercel.app)

**Address:** `0x508B9fddeA8cE3C097B71A7e9Fa6E9Cc04496d36`
**Chain:** Studionet (Genlayer Studio Network)
**Deployer:** `0x689759bb926E032EAfb1eE986eD7A98C1496ec1c`
**Tx:** `0xe1e205f0c9bcb8b4a8464c144b9941cf939419abc1885f8d0f79a39ac31e0f96`
**Source:** `contracts/milestone_escrow.py` — identical to the submitted source (the deployed bytecode is produced from this file)
**Source SHA-256:** `5E4C5DB496DD8BBADE5915E194F8943D8F592FFF8F55AB1108AEF5A3EBA528C1` (file unchanged since the deploy tx above)
**Status:** Deployed and tested on studionet. E2E scenarios [A] and [B] pass (release with live GEN payout, permanent fetch failure recorded + funder refund). 38/38 direct-mode tests pass. All functions operational: create_escrow, submit_proof, verify_escrow, cancel_escrow, reclaim_expired, refund_failed_escrow, views.

**Superseded v1:** `0xED3E9616582ffb30f47F75866ba97Caf71a4540c` (tx `0xe47b95cc5accd2b855647c9a2c6147a48ee3af5c5e1e3b0f6ec1354b1998970e`) — no trusted fetch path and no recovery path from `proof_submitted`; use v2 above.


---

## Extension ideas

- Multi-worker milestone chains (sequenced milestones releasing tranches automatically)
- Partial delivery scoring (proportional payout instead of binary release/refund)
- Arbiter role for post-settlement disputes with additional evidence rounds
- Integration with SkillRegistry / BountyBoard for worker reputation-weighted scoring
