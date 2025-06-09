# Bitcoin Wallet Generator

This is a Python-based Bitcoin wallet generator with balance checking and a Tkinter GUI.

---

## Features

- Generate BIP39 mnemonic phrases
- Derive Legacy Bitcoin addresses
- Check balance via Blockstream API
- Dark mode toggle in GUI
- Auto-save wallets with balance to `found_wallets.txt`

---

## Requirements

- Python 3.8+
- Modules: `tkinter`, `ecdsa`, `requests`, `base58`, `Pillow`

Install dependencies via:

```bash
pip install ecdsa requests base58 Pillow
