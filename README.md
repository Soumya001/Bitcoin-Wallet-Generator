# 🟠 Bitcoin Wallet Generator (Tkinter GUI)

A Python-based Bitcoin wallet generator with GUI, mnemonic support, balance checker, dark mode, and auto-save functionality.
For teaching purpose only.
---

## ✅ Features

- Generates BIP39 12-word mnemonics
- Derives WIF private keys and legacy Bitcoin addresses
- Checks wallet balance using Blockstream API
- Saves wallets with balance to `found_wallets.txt`
- Threaded UI and dark mode toggle

---

## 🛠 Requirements

- Python 3.8 or newer

Install dependencies:

```bash
pip install ecdsa requests base58 Pillow
