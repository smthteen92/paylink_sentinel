#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
paylink-sentinel — offline linter & risk scorer for crypto payment links/QR content.

Supports:
  • ethereum:  (EIP-681 style)  ethereum:0xADDR[@CHAIN]?value=...&gas=...&gasPrice=...&data=...
  • bitcoin:   (BIP-21)         bitcoin:ADDR?amount=...&label=...&message=...
  • solana:    (simple)         solana:ADDR?amount=...&label=...&memo=...

Flags suspicious patterns and prints a readable summary, JSON report, and optional SVG badge.

Examples:
  $ python paylink_sentinel.py scan "ethereum:0xabc...@1?value=1e18&data=0x095ea7b3..."
  $ python paylink_sentinel.py scan links.txt --json report.json --svg badge.svg --pretty
"""

import json
import math
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

import click
from eth_utils import to_checksum_address

# ------------ Helpers ------------

APPROVE_SEL = "095ea7b3"
SET_APPROVAL_FOR_ALL_SEL = "a22cb465"
TRANSFER_SEL = "a9059cbb"
TRANSFER_FROM_SEL = "23b872dd"
# Common EIP-2612 permit selector (varies across impls; this is the canonical one)
PERMIT_SEL = "d505accf"

ETH_VALUE_KEYS = ("value", "uint256", "amount")  # EIP-681 allows value; some wallets use amount

BTC_ADDR_RE = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$", re.IGNORECASE)
SOL_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

def parse_amount(val: str) -> Optional[float]:
    try:
        # Supports decimals and scientific (e.g., 1e18). For ETH/BTC this is in native units.
        return float(val)
    except Exception:
        return None

def hexstr(s: str) -> str:
    h = s.lower()
    return h if h.startswith("0x") else "0x" + h

def first_selector(data_hex: str) -> str:
    h = data_hex.lower()
    if h.startswith("0x"):
        h = h[2:]
    return h[:8] if len(h) >= 8 else ""

def eth_value_to_eth(val: float) -> float:
    # If someone passes wei (common in EIP-681 value), they often provide integer like 1000000000000000000.
    # Heuristic: if val is an integer >= 1e9, treat as wei; else treat as ETH.
    if val >= 1e9 and abs(val - int(val)) < 1e-9:
        return val / 1e18
    return val

def is_eth_checksum_ok(addr: str) -> bool:
    # If address is all lower/upper, EIP-55 checksum isn't present; flag as weaker.
    # If mixed case, verify by comparing to EIP-55 output.
    core = addr[2:]
    if core.islower() or core.isupper():
        return False
    try:
        return to_checksum_address(addr) == addr
    except Exception:
        return False

# ------------ Data classes ------------

@dataclass
class Finding:
    level: str   # LOW / MEDIUM / HIGH
    reason: str
    context: Dict

@dataclass
class Report:
    scheme: str
    target: str
    summary: Dict
    findings: List[Finding]
    risk_score: int
    risk_label: str

# ------------ Parsers ------------

def parse_ethereum(uri: str) -> Tuple[Dict, List[Finding]]:
    fs: List[Finding] = []
    u = urlparse(uri)
    # Path form may contain 'pay-' or raw address and optional '@chain'
    raw = (u.path or "").strip()  # e.g. "0xabc...@1" or "pay-0xabc...@10" or ""
    if raw.startswith("pay-"):
        raw = raw[4:]
    # Some wallets put address in netloc for "ethereum://0x..." — normalize
    if not raw and u.netloc:
        raw = u.netloc

    address = raw
    chain_id = None
    if "@" in raw:
        address, chain = raw.split("@", 1)
        chain_id = chain.strip()

    address = address.strip()
    q = {k: v[0] for k, v in parse_qs(u.query).items() if v}

    # Extract value
    raw_value = None
    for k in ETH_VALUE_KEYS:
        if k in q:
            raw_value = q[k]
            break
    value_eth = None
    if raw_value is not None:
        amt = parse_amount(raw_value)
        if amt is not None:
            value_eth = eth_value_to_eth(amt)

    data = q.get("data")
    gas = q.get("gas")
    gas_price = q.get("gasPrice") or q.get("gasprice")
    function = q.get("function")  # some EIP-681 forms allow function name

    # Findings
    if address:
        if not address.lower().startswith("0x") or len(address) != 42:
            fs.append(Finding("HIGH", "Malformed Ethereum address", {"address": address}))
        else:
            if not is_eth_checksum_ok(address):
                fs.append(Finding("MEDIUM", "Address not checksummed (EIP-55)", {"address": address}))
    else:
        fs.append(Finding("HIGH", "Missing Ethereum address", {}))

    if chain_id:
        try:
            cid = int(chain_id)
            if cid not in (1, 10, 56, 137, 8453, 42161, 43114, 11155111):  # common nets incl. Sepolia
                fs.append(Finding("LOW", "Uncommon chain id", {"chain_id": cid}))
        except Exception:
            fs.append(Finding("MEDIUM", "Invalid chain id", {"chain_id": chain_id}))

    if value_eth is not None:
        if value_eth < 0:
            fs.append(Finding("HIGH", "Negative value", {"value_eth": value_eth}))
        elif value_eth >= 100:  # heuristic large send
            fs.append(Finding("HIGH", "Very large ETH amount", {"value_eth": value_eth}))
        elif value_eth > 0:
            fs.append(Finding("MEDIUM", "Sends native ETH", {"value_eth": value_eth}))

    if gas:
        try:
            g = int(gas, 0)
            if g > 5_000_000:
                fs.append(Finding("LOW", "Unusually high gas limit requested", {"gas": g}))
        except Exception:
            fs.append(Finding("LOW", "Invalid gas value", {"gas": gas}))

    if gas_price:
        try:
            gp = int(gas_price, 0)
            if gp > 500_000_000_000:  # 500 Gwei in wei
                fs.append(Finding("LOW", "High gasPrice hint", {"gasPrice": gp}))
        except Exception:
            fs.append(Finding("LOW", "Invalid gasPrice", {"gasPrice": gas_price}))

    if data:
        sel = first_selector(data)
        if sel in (APPROVE_SEL, SET_APPROVAL_FOR_ALL_SEL):
            lev = "HIGH" if sel == SET_APPROVAL_FOR_ALL_SEL else "HIGH"
            label = "setApprovalForAll" if sel == SET_APPROVAL_FOR_ALL_SEL else "approve"
            fs.append(Finding(lev, f"Suspicious token permission method in data: {label}", {"selector": "0x"+sel}))
        elif sel in (TRANSFER_SEL, TRANSFER_FROM_SEL, PERMIT_SEL):
            label = {"a9059cbb":"transfer","23b872dd":"transferFrom","d505accf":"permit"}[sel]
            fs.append(Finding("MEDIUM", f"Token {label} embedded in payment link", {"selector":"0x"+sel}))
        elif sel:
            fs.append(Finding("LOW", "Unknown method selector present", {"selector": "0x"+sel}))
        if "0x" not in data.lower():
            fs.append(Finding("MEDIUM", "Non-hex data payload", {"data": data}))

    # Duplicate parameters heuristic
    dup_keys = [k for k, vs in parse_qs(u.query).items() if len(vs) > 1]
    if dup_keys:
        fs.append(Finding("LOW", "Duplicate query parameters", {"keys": dup_keys}))

    summary = {
        "address": address or "",
        "chain_id": chain_id,
        "value_eth": value_eth,
        "has_data": bool(data),
        "function_hint": function,
        "gas": gas,
        "gasPrice": gas_price,
        "raw_query": q
    }
    return summary, fs

def parse_bitcoin(uri: str) -> Tuple[Dict, List[Finding]]:
    fs: List[Finding] = []
    u = urlparse(uri)
    address = (u.path or "").strip() or (u.netloc or "").strip()
    q = {k: v[0] for k, v in parse_qs(u.query).items() if v}
    amt = parse_amount(q.get("amount", "")) if "amount" in q else None

    if not address or not BTC_ADDR_RE.match(address):
        fs.append(Finding("MEDIUM", "Address format unusual for BIP-21", {"address": address}))

    if amt is not None:
        if amt < 0:
            fs.append(Finding("HIGH", "Negative BTC amount", {"amount_btc": amt}))
        elif amt >= 10:
            fs.append(Finding("HIGH", "Very large BTC amount", {"amount_btc": amt}))
        elif amt > 0:
            fs.append(Finding("LOW", "Sends BTC", {"amount_btc": amt}))

    summary = {"address": address, "amount_btc": amt, "label": q.get("label"), "message": q.get("message")}
    return summary, fs

def parse_solana(uri: str) -> Tuple[Dict, List[Finding]]:
    fs: List[Finding] = []
    u = urlparse(uri)
    address = (u.path or "").strip() or (u.netloc or "").strip()
    q = {k: v[0] for k, v in parse_qs(u.query).items() if v}
    amt = parse_amount(q.get("amount", "")) if "amount" in q else None

    if not address or not SOL_ADDR_RE.match(address):
        fs.append(Finding("MEDIUM", "Address format unusual for Solana", {"address": address}))

    if amt is not None:
        if amt < 0:
            fs.append(Finding("HIGH", "Negative SOL amount", {"amount_sol": amt}))
        elif amt >= 10_000:
            fs.append(Finding("HIGH", "Very large SOL amount", {"amount_sol": amt}))
        elif amt > 0:
            fs.append(Finding("LOW", "Sends SOL", {"amount_sol": amt}))

    summary = {"address": address, "amount_sol": amt, "label": q.get("label"), "memo": q.get("memo")}
    return summary, fs

# ------------ Risk aggregation ------------

def score(findings: List[Finding]) -> Tuple[int, str]:
    pts = 0
    for f in findings:
        if f.level == "HIGH":
            pts += 35
        elif f.level == "MEDIUM":
            pts += 15
        else:
            pts += 5
    pts = min(100, pts)
    label = "HIGH" if pts >= 70 else "MEDIUM" if pts >= 30 else "LOW"
    return pts, label

# ------------ CLI ------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """paylink-sentinel — lint & risk-score crypto payment links (offline)."""
    pass

def scan_one(text: str) -> Report:
    s = text.strip()
    if not s:
        raise click.ClickException("Empty line or input.")
    # Accept raw lines that may be URL-encoded
    s = unquote(s)

    u = urlparse(s)
    scheme = (u.scheme or "").lower()
    findings: List[Finding] = []
    summary: Dict = {}

    if scheme == "ethereum":
        summary, findings = parse_ethereum(s)
        target = summary.get("address","")
    elif scheme == "bitcoin":
        summary, findings = parse_bitcoin(s)
        target = summary.get("address","")
    elif scheme == "solana":
        summary, findings = parse_solana(s)
        target = summary.get("address","")
    else:
        raise click.ClickException(f"Unsupported scheme: {scheme or '<none>'}")

    score_val, label = score(findings)
    return Report(
        scheme=scheme,
        target=target,
        summary=summary,
        findings=findings,
        risk_score=score_val,
        risk_label=label
    )

@cli.command("scan")
@click.argument("input_arg", type=str)
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON array report.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write tiny SVG risk badge.")
@click.option("--pretty", is_flag=True, help="Human-readable console output.")
def scan_cmd(input_arg, json_out, svg_out, pretty):
    """
    Scan a single URI string, a file path containing multiple URIs (one per line), or '-' for stdin.
    """
    lines: List[str] = []
    if input_arg == "-":
        lines = [l.rstrip("\n") for l in sys.stdin]
    elif os.path.isfile(input_arg):
        with open(input_arg, "r", encoding="utf-8") as f:
            lines = [l.rstrip("\n") for l in f]
    else:
        lines = [input_arg]

    reports: List[Report] = []
    for ln in lines:
        if not ln.strip():
            continue
        try:
            rep = scan_one(ln)
            reports.append(rep)
        except click.ClickException as e:
            # Capture as HIGH finding for visibility
            reports.append(Report(
                scheme="unknown", target="",
                summary={"raw": ln},
                findings=[Finding("HIGH","Parse error",{"error": str(e)})],
                risk_score=100, risk_label="HIGH"
            ))

    # Console output
    if pretty:
        for r in reports:
            click.echo(f"[{r.scheme}] {r.target or '<no target>'}  risk {r.risk_score}/100 ({r.risk_label})")
            for f in r.findings:
                click.echo(f"   - {f.level}: {f.reason} {f.context}")
        if not reports:
            click.echo("No inputs processed.")

    # JSON
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump([{
                "scheme": r.scheme,
                "target": r.target,
                "summary": r.summary,
                "risk_score": r.risk_score,
                "risk_label": r.risk_label,
                "findings": [asdict(x) for x in r.findings],
            } for r in reports], f, indent=2)
        click.echo(f"Wrote JSON report: {json_out}")

    # Badge based on worst risk
    if svg_out:
        worst = max((r.risk_score for r in reports), default=0)
        label = "HIGH" if worst >= 70 else "MEDIUM" if worst >= 30 else "LOW"
        color = "#3fb950" if worst < 30 else "#d29922" if worst < 70 else "#f85149"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="380" height="48" role="img" aria-label="Paylink risk">
  <rect width="380" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    paylink-sentinel: worst {worst}/100 ({label})
  </text>
  <circle cx="355" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

    # Default: print JSON to stdout if nothing else chosen
    if not (pretty or json_out or svg_out):
        click.echo(json.dumps([{
            "scheme": r.scheme,
            "target": r.target,
            "summary": r.summary,
            "risk_score": r.risk_score,
            "risk_label": r.risk_label,
            "findings": [asdict(x) for x in r.findings],
        } for r in reports], indent=2))

if __name__ == "__main__":
    cli()
