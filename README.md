# paylink-sentinel — lint & risk-score crypto payment links (offline)

**paylink-sentinel** is an offline CLI that parses crypto URIs / QR contents and flags risky
patterns *before* you scan or sign. It understands:

- **EIP-681** `ethereum:` links (e.g., `ethereum:0xADDR@1?value=...&data=...`)
- **BIP-21** `bitcoin:` links (amount/label/message)
- Simple **`solana:`** links (amount/label/memo)

It highlights wrong chain IDs, non-checksummed ETH addresses, huge requested amounts, suspicious
`data` selectors like **`approve`** or **`setApprovalForAll`**, duplicate parameters, and more.
No RPC calls. No internet. Just paste the link content.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
