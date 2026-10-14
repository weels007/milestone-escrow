# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""MilestoneEscrow — Consensus-Gated Milestone Escrow with Live Payout

> A funder deposits GEN for a milestone; the worker proves delivery with a
> URL; validators independently fetch the evidence and score it under
> consensus. A verified verdict pays the worker via an external transfer; a
> rejected verdict, a cancellation, or an expired deadline refunds the funder.

Unique patterns:
  1. Real custody: payable intake, consensus-gated live payout (EthSend)
  2. Multi-escrow liability accounting (locked_total guards other escrows)
  3. Proof-of-delivery verification with SSRF/DNS-rebinding defense
  4. Score tolerance so independent LLM runs can reach consensus
  5. Address coercion for entry args (client sends addresses as strings)
"""

import json
import re
import ipaddress
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from dataclasses import dataclass

from genlayer import *
from genlayer.py.keccak import Keccak256

MIN_PROOF_CHARS = 20
MAX_PROOF_CHARS = 2000
MAX_MILESTONE_CHARS = 300
MAX_DESCRIPTION_CHARS = 500
MAX_URL_CHARS = 2048
MIN_SCORE = 60
SCORE_TOLERANCE = 10

ERROR_LLM = "[LLM] "
ERROR_EXTERNAL = "[EXTERNAL] "
ERROR_TRANSIENT = "[TRANSIENT] "
ERROR_EXPECTED = "[EXPECTED] "


def _now_ts() -> int:
    try:
        dt = datetime.now(timezone.utc)
        return int(dt.timestamp())
    except Exception:
        pass
    try:
        raw = gl.message_raw["datetime"]
        if not raw:
            return 0
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return 0


def _addr_hex(addr) -> str:
    if hasattr(addr, "as_hex"):
        return str(addr.as_hex).lower().replace("0x", "")
    if hasattr(addr, "as_bytes"):
        return bytes(addr.as_bytes).hex().lower()
    if hasattr(addr, "hex"):
        return addr.hex().lower()
    if hasattr(addr, "__bytes__"):
        return bytes(addr).hex().lower()
    return str(addr).lower().replace("0x", "")


def _addr_eq(a, b) -> bool:
    return _addr_hex(a) == _addr_hex(b)


def _secp_inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _secp_add(p, q):
    _SECP256K1_P = 2**256 - 2**32 - 977
    _SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    _SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _SECP256K1_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * _secp_inv(2 * p[1], _SECP256K1_P) % _SECP256K1_P
    else:
        lam = (q[1] - p[1]) * _secp_inv(q[0] - p[0], _SECP256K1_P) % _SECP256K1_P
    x = (lam * lam - p[0] - q[0]) % _SECP256K1_P
    y = (lam * (p[0] - x) - p[1]) % _SECP256K1_P
    return (x, y)


def _secp_mul(k: int, pt):
    if k == 0 or pt is None:
        return None
    if k < 0:
        return _secp_mul(-k, (pt[0], (-pt[1]) % _SECP256K1_P))
    result = None
    while k:
        if k & 1:
            result = _secp_add(result, pt)
        pt = _secp_add(pt, pt)
        k >>= 1
    return result


_SECP256K1_P = 2**256 - 2**32 - 977
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _keccak256(data) -> bytes:
    return Keccak256(data).digest()


def _eip191_digest(message: str) -> bytes:
    raw = message.encode("utf-8")
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(raw)).encode("ascii")
    return _keccak256(prefix + raw)


def _ecrecover(msg_hash: bytes, r: int, s: int, v: int):
    try:
        recid = (v - 27) & 3
        z = int.from_bytes(msg_hash, "big")
        x = r + (recid >> 1) * _SECP256K1_N
        if x >= _SECP256K1_P:
            return None
        y2 = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
        y = pow(y2, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
        if (y & 1) != (recid & 1):
            y = _SECP256K1_P - y
        R = (x, y)
        rinv = _secp_inv(r, _SECP256K1_N)
        sR = _secp_mul(s, R)
        zG = _secp_mul(z % _SECP256K1_N, (_SECP256K1_GX, _SECP256K1_GY))
        neg_zG = (zG[0], (-zG[1]) % _SECP256K1_P)
        Q = _secp_mul(rinv, _secp_add(sR, neg_zG))
        if Q is None:
            return None
        if Q[0] >= _SECP256K1_P or Q[1] >= _SECP256K1_P:
            return None
        pub = bytes([4]) + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
        return "0x" + _keccak256(pub[1:])[12:].hex()
    except Exception:
        return None


def _signer_of(sign_msg: str, signature: str):
    if not signature or not signature.startswith("0x"):
        return None
    try:
        sig_bytes = bytes.fromhex(signature[2:])
    except ValueError:
        return None
    if len(sig_bytes) != 65:
        return None
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:64], "big")
    v = sig_bytes[64]
    msg_hash = _eip191_digest(sign_msg)
    recovered = _ecrecover(msg_hash, r, s, v)
    return recovered.lower().replace("0x", "") if recovered else None


_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_BLOCKED_HOST_SUFFIXES = (".local", ".internal", ".localhost", ".nip.io", ".sslip.io")
_BLOCKED_HOST_KEYWORDS = ("localhost", "metadata.google")
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def _parse_inet_literal(host: str):
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    nums = []
    for p in parts:
        if not p:
            return None
        try:
            if p.lower().startswith("0x"):
                n = int(p, 16)
            elif len(p) > 1 and p.startswith("0"):
                n = int(p, 8)
            elif p.isdigit():
                n = int(p, 10)
            else:
                return None
        except ValueError:
            return None
        nums.append(n)
    if len(nums) == 4:
        if any(n > 255 for n in nums):
            return None
        value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
    elif len(nums) == 3:
        if nums[0] > 255 or nums[1] > 255 or nums[2] > 0xFFFFFF:
            return None
        value = (nums[0] << 16) | (nums[1] << 8) | nums[2]
    elif len(nums) == 2:
        if nums[0] > 255:
            return None
        value = (nums[0] << 24) | nums[1]
    else:
        if nums[0] > 0xFFFFFFFF:
            return None
        value = nums[0]
    if value > 0xFFFFFFFF:
        return None
    return f"{(value >> 24) & 0xff}.{(value >> 16) & 0xff}.{(value >> 8) & 0xff}.{value & 0xff}"


def _ip_is_blocked(ip) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True
    if ip.version == 4 and ip in _CGNAT_V4:
        return True
    return False


def _host_is_blocked(host: str) -> bool:
    host_l = host.lower().rstrip(".")
    if any(kw in host_l for kw in _BLOCKED_HOST_KEYWORDS):
        return True
    if any(host_l.endswith(sfx) for sfx in _BLOCKED_HOST_SUFFIXES):
        return True
    candidate = _parse_inet_literal(host_l) or host_l
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return _ip_is_blocked(ip)


def _validate_url(url: str) -> bool:
    if not url or len(url) > MAX_URL_CHARS:
        return False
    if not _URL_RE.match(url):
        return False
    if _CONTROL_RE.search(url):
        return False
    if "\\" in url:
        return False
    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if not host:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    return not _host_is_blocked(host)


@gl.evm.contract_interface
class _EOA:
    class View:
        pass

    class Write:
        pass


def _pay_out(to, value: int) -> None:
    """Send GEN to an EOA via an external EthSend message.

    Client-supplied addresses arrive as plain strings (genlayer-js encodes
    them as calldata strings), so coerce to Address before building the
    payload — otherwise the executor rejects the message with SystemError 2.

    Liability accounting lives in locked_total (storage); self.balance is
    not consulted because it is unreliable outside on-chain execution.
    """
    if value <= 0:
        raise gl.vm.UserError("payout must be positive")
    if not hasattr(to, "as_bytes"):
        to = Address(to)
    _EOA(to).emit_transfer(value=u256(value), on="finalized")


def _score_proof(milestone: str, proof_content: str) -> int:
    prompt = f"""Score this proof of milestone delivery for an escrow contract.

Milestone: {milestone}

Proof content: {proof_content}

Score 0-100 based on:
- Demonstrates the milestone was actually delivered (0-40)
- Relevant to the stated milestone (0-30)
- Specific and verifiable (0-20)
- Not vague or generic (0-20)

Return ONLY JSON: {{"score": 0-100}}"""
    try:
        out = gl.nondet.exec_prompt(prompt, response_format="json")
    except Exception:
        raise gl.vm.UserError(ERROR_LLM + "Proof scoring failed")
    if not isinstance(out, dict) or "score" not in out:
        raise gl.vm.UserError(ERROR_LLM + "Invalid proof scoring")
    try:
        return max(0, min(100, int(out["score"])))
    except (ValueError, TypeError):
        raise gl.vm.UserError(ERROR_LLM + "Invalid score")


@allow_storage
@dataclass
class Escrow:
    escrow_id: str
    funder: Address
    worker: Address
    amount: u256
    milestone: str
    deadline: u256
    status: str
    proof_score: u256
    created_ts: u256


@allow_storage
@dataclass
class Proof:
    escrow_id: str
    submitter: Address
    url: str
    description: str
    submitted_ts: u256


class MilestoneEscrow(gl.Contract):
    escrows: TreeMap[str, Escrow]
    proofs: TreeMap[str, Proof]
    escrow_seq: u256
    locked_total: u256

    def __init__(self):
        pass

    @gl.public.write.payable
    def create_escrow(self, worker: Address, milestone: str, deadline: int) -> str:
        if not milestone or len(milestone) > MAX_MILESTONE_CHARS:
            raise gl.vm.UserError(f"milestone must be 1-{MAX_MILESTONE_CHARS} characters")
        if deadline <= _now_ts():
            raise gl.vm.UserError("deadline must be in the future")
        if not hasattr(worker, "as_bytes"):
            worker = Address(worker)
        sender = gl.message.sender_address
        if _addr_eq(sender, worker):
            raise gl.vm.UserError("funder and worker must differ")
        value = int(gl.message.value)
        if value <= 0:
            raise gl.vm.UserError("must deposit a positive amount")
        funder_hex = _addr_hex(sender)
        seq = int(self.escrow_seq)
        escrow_id = f"{funder_hex}:{seq}"
        self.escrows[escrow_id] = Escrow(
            escrow_id=escrow_id,
            funder=sender,
            worker=worker,
            amount=u256(value),
            milestone=milestone,
            deadline=u256(deadline),
            status="open",
            proof_score=0,
            created_ts=u256(_now_ts()),
        )
        self.escrow_seq = self.escrow_seq + 1
        self.locked_total = self.locked_total + u256(value)
        return escrow_id

    @gl.public.write
    def submit_proof(self, escrow_id: str, url: str, description: str, signature: str) -> None:
        if escrow_id not in self.escrows:
            raise gl.vm.UserError("escrow not found")
        escrow = self.escrows[escrow_id]
        if escrow.status != "open":
            raise gl.vm.UserError("escrow not open")
        if _now_ts() > int(escrow.deadline):
            raise gl.vm.UserError("deadline passed")
        if not _validate_url(url):
            raise gl.vm.UserError("invalid url")
        if not description or len(description) > MAX_DESCRIPTION_CHARS:
            raise gl.vm.UserError(f"description must be 1-{MAX_DESCRIPTION_CHARS} characters")
        sender = gl.message.sender_address
        if not _addr_eq(sender, escrow.worker):
            raise gl.vm.UserError("only worker can submit proof")
        proof_key = f"{escrow_id}:proof"
        if proof_key in self.proofs:
            raise gl.vm.UserError("proof already submitted")
        worker_hex = _addr_hex(escrow.worker)
        sign_msg = f"MilestoneEscrow:proof:{escrow_id}:{url}:{description[:50]}"
        signer = _signer_of(sign_msg, signature)
        if signer is None or signer != worker_hex:
            raise gl.vm.UserError("invalid proof signature")
        self.proofs[proof_key] = Proof(
            escrow_id=escrow_id,
            submitter=sender,
            url=url,
            description=description,
            submitted_ts=u256(_now_ts()),
        )
        escrow.status = "proof_submitted"
        self.escrows[escrow_id] = escrow

    @gl.public.write
    def verify_escrow(self, escrow_id: str) -> None:
        if escrow_id not in self.escrows:
            raise gl.vm.UserError("escrow not found")
        escrow = self.escrows[escrow_id]
        if escrow.status != "proof_submitted":
            raise gl.vm.UserError("proof not submitted")
        proof_key = f"{escrow_id}:proof"
        if proof_key not in self.proofs:
            raise gl.vm.UserError("proof not found")
        proof = self.proofs[proof_key]
        result = _run_escrow_consensus(escrow_id, escrow, proof)
        self.locked_total = self.locked_total - escrow.amount
        escrow.proof_score = result["proof_score"]
        escrow.status = "released" if result["verified"] else "refunded"
        self.escrows[escrow_id] = escrow
        target = escrow.worker if result["verified"] else escrow.funder
        _pay_out(target, int(escrow.amount))

    @gl.public.write
    def cancel_escrow(self, escrow_id: str) -> None:
        if escrow_id not in self.escrows:
            raise gl.vm.UserError("escrow not found")
        escrow = self.escrows[escrow_id]
        if escrow.status != "open":
            raise gl.vm.UserError("escrow not open")
        sender = gl.message.sender_address
        if not _addr_eq(sender, escrow.funder):
            raise gl.vm.UserError("only funder can cancel")
        self.locked_total = self.locked_total - escrow.amount
        escrow.status = "refunded"
        self.escrows[escrow_id] = escrow
        _pay_out(escrow.funder, int(escrow.amount))

    @gl.public.write
    def reclaim_expired(self, escrow_id: str) -> None:
        if escrow_id not in self.escrows:
            raise gl.vm.UserError("escrow not found")
        escrow = self.escrows[escrow_id]
        if escrow.status != "open":
            raise gl.vm.UserError("escrow not open")
        if _now_ts() <= int(escrow.deadline):
            raise gl.vm.UserError("deadline not passed")
        sender = gl.message.sender_address
        if not _addr_eq(sender, escrow.funder):
            raise gl.vm.UserError("only funder can reclaim")
        self.locked_total = self.locked_total - escrow.amount
        escrow.status = "refunded"
        self.escrows[escrow_id] = escrow
        _pay_out(escrow.funder, int(escrow.amount))

    @gl.public.view
    def get_escrow(self, escrow_id: str) -> dict:
        if escrow_id not in self.escrows:
            return {}
        e = self.escrows[escrow_id]
        return {
            "escrow_id": e.escrow_id,
            "funder": _addr_hex(e.funder),
            "worker": _addr_hex(e.worker),
            "amount": int(e.amount),
            "milestone": e.milestone,
            "deadline": int(e.deadline),
            "status": e.status,
            "proof_score": int(e.proof_score),
            "created_ts": int(e.created_ts),
        }

    @gl.public.view
    def get_proof(self, escrow_id: str) -> dict:
        key = f"{escrow_id}:proof"
        if key not in self.proofs:
            return {}
        p = self.proofs[key]
        return {
            "escrow_id": p.escrow_id,
            "submitter": _addr_hex(p.submitter),
            "url": p.url,
            "description": p.description,
            "submitted_ts": int(p.submitted_ts),
        }

    @gl.public.view
    def get_funder_escrows(self, funder: Address) -> list:
        addr_hex = _addr_hex(funder)
        out = []
        for _k, e in self.escrows.items():
            if _addr_hex(e.funder) == addr_hex:
                out.append({
                    "escrow_id": e.escrow_id,
                    "worker": _addr_hex(e.worker),
                    "amount": int(e.amount),
                    "status": e.status,
                    "proof_score": int(e.proof_score),
                })
        return out

    @gl.public.view
    def escrow_totals(self) -> dict:
        return {
            "locked_total": int(self.locked_total),
        }


MAX_REDIRECTS = 5


def _header_value(res, name: str):
    try:
        headers = getattr(res, "headers", None) or {}
        for k, v in headers.items():
            if str(k).lower() == name:
                if isinstance(v, (bytes, bytearray)):
                    return bytes(v).decode("utf-8", errors="replace")
                return str(v)
    except Exception:
        return None
    return None


def _host_of(url: str):
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _doh_lookup(name: str, qtype: str) -> list:
    doh_url = "https://dns.google/resolve?name=" + name + "&type=" + qtype
    try:
        res = gl.nondet.web.get(doh_url)
    except gl.vm.UserError:
        raise
    except Exception:
        raise gl.vm.UserError(ERROR_TRANSIENT + "DNS resolution failed")
    status = int(res.status)
    if status >= 500:
        raise gl.vm.UserError(ERROR_TRANSIENT + "DNS resolution failed")
    if status >= 400:
        raise gl.vm.UserError(ERROR_EXTERNAL + f"DNS resolver returned {status}")
    try:
        data = json.loads((res.body or b"").decode("utf-8", errors="replace"))
    except Exception:
        raise gl.vm.UserError(ERROR_EXTERNAL + "invalid DNS response")
    if not isinstance(data, dict):
        raise gl.vm.UserError(ERROR_EXTERNAL + "invalid DNS response")
    ips = []
    for ans in (data.get("Answer") or []):
        if not isinstance(ans, dict):
            continue
        if ans.get("type") not in (1, 28):
            continue
        ips.append(str(ans.get("data", "")))
    return ips


def _resolve_host_ips(host: str) -> list:
    host_l = (host or "").lower().rstrip(".")
    literal = _parse_inet_literal(host_l)
    if literal:
        return [literal]
    try:
        ipaddress.ip_address(host_l)
        return [host_l]
    except ValueError:
        pass
    raws = _doh_lookup(host_l, "A") + _doh_lookup(host_l, "AAAA")
    ips = []
    for raw in raws:
        try:
            ips.append(str(ipaddress.ip_address(raw)))
        except ValueError:
            continue
    return ips


def _ensure_resolved_safe(host: str) -> None:
    ips = _resolve_host_ips(host)
    if not ips:
        raise gl.vm.UserError(ERROR_EXTERNAL + "host did not resolve")
    for raw in ips:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            raise gl.vm.UserError(ERROR_EXTERNAL + "resolved address is blocked")


def _fetch_proof_evidence(url: str) -> str:
    if not _validate_url(url):
        raise gl.vm.UserError(ERROR_EXPECTED + "invalid url")
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        host = _host_of(current)
        if not host:
            raise gl.vm.UserError(ERROR_EXTERNAL + "invalid redirect target")
        _ensure_resolved_safe(host)
        try:
            res = gl.nondet.web.get(current)
        except gl.vm.UserError:
            raise
        except Exception:
            raise gl.vm.UserError(ERROR_TRANSIENT + "URL fetch failed")
        status = int(res.status)
        if 300 <= status < 400:
            location = _header_value(res, "location")
            if not location:
                raise gl.vm.UserError(ERROR_EXTERNAL + f"redirect without location ({status})")
            if _hop == MAX_REDIRECTS:
                raise gl.vm.UserError(ERROR_EXPECTED + "redirect limit exceeded")
            current = urljoin(current, location)
            if not _validate_url(current):
                raise gl.vm.UserError(ERROR_EXTERNAL + "blocked redirect target")
            continue
        if 400 <= status < 500:
            raise gl.vm.UserError(ERROR_EXTERNAL + f"URL returned {status}")
        if status >= 500:
            raise gl.vm.UserError(ERROR_TRANSIENT + f"URL temporarily unavailable ({status})")
        return (res.body or b"").decode("utf-8", errors="replace")[:MAX_PROOF_CHARS]
    raise gl.vm.UserError(ERROR_EXPECTED + "redirect limit exceeded")


def _fields_agree(mine, theirs) -> bool:
    if not isinstance(mine, dict) or not isinstance(theirs, dict):
        return False
    if mine.get("verified") is not theirs.get("verified"):
        return False
    try:
        my_score = int(mine.get("proof_score", -1))
        lead_score = int(theirs.get("proof_score", -1))
    except (ValueError, TypeError):
        return False
    return abs(my_score - lead_score) <= SCORE_TOLERANCE


def _run_escrow_consensus(escrow_id: str, escrow: Escrow, proof: Proof) -> dict:
    def leader_fn():
        milestone = escrow.milestone
        content = _fetch_proof_evidence(proof.url)
        evidence = f"URL: {proof.url}\nFetched content:\n{content}\n\nDescription: {proof.description}"
        score = _score_proof(milestone, evidence)
        verified = score >= MIN_SCORE
        return {
            "verified": verified,
            "proof_score": score,
        }

    def validator_fn(leader_result):
        if not isinstance(leader_result, gl.vm.Return):
            return _reproduce_leader_error(leader_result, leader_fn)
        leader_data = leader_result.calldata
        if not isinstance(leader_data, dict):
            return False
        my = leader_fn()
        return _fields_agree(my, leader_data)

    return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)


def _reproduce_leader_error(leader_result, leader_fn) -> bool:
    leader_msg = getattr(leader_result, "message", "") or ""
    try:
        leader_fn()
        return False
    except gl.vm.UserError as e:
        v_msg = e.message if hasattr(e, "message") else str(e)
        if v_msg.startswith(ERROR_EXPECTED) or v_msg.startswith(ERROR_EXTERNAL):
            return v_msg == leader_msg
        if v_msg.startswith(ERROR_TRANSIENT) and leader_msg.startswith(ERROR_TRANSIENT):
            return True
        return False
    except Exception:
        return False
