# Blockchain Tools

A single-file Flask web app for experimenting with blockchain concepts. It runs
a small web UI with several tools side by side: a "simple" chain, a "secure"
mined chain, a live Bitcoin block explorer, and an ECDSA wallet generator.

## Features

- **Simple chain** — add/delete blocks and see how each block links to the
  previous one via its hash.
- **Secure chain** — proof-of-work mining with adjustable difficulty.
- **Explorer** — fetches and displays real Bitcoin block data.
- **Wallet** — generates ECDSA (SECP256k1) key pairs.
- Chains are persisted to local JSON files (`db_simple.json`, `db_secure.json`).

## Requirements

- Python 3.8+

The script auto-installs its dependencies (`flask`, `crcmod`, `requests`,
`ecdsa`) on first run. To install them manually instead:

```bash
pip install flask crcmod requests ecdsa
```

## Running

```bash
python blockchain.py
```

Then open <http://127.0.0.1:5000/> in your browser.

> ⚠️ Runs with Flask's debug server — for learning/local use only, not
> production.
