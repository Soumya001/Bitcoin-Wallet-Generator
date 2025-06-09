import tkinter as tk
import hashlib
import base58
import ecdsa
import requests
import secrets
import sys
import os
import webbrowser
import threading
import time

# --- Globals ---
searching = False
wallet_found = False
dark_mode = False

# --- Resource Path Helper (for PyInstaller) ---
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- Load BIP39 Wordlist ---
with open(resource_path("bip39_english_wordlist.txt"), "r") as f:
    WORDLIST = [word.strip() for word in f.readlines()]

# --- Bitcoin Wallet Functions ---
def generate_mnemonic():
    entropy = secrets.token_bytes(16)
    entropy_bits = bin(int.from_bytes(entropy, byteorder="big"))[2:].zfill(128)
    checksum_bits = bin(int(hashlib.sha256(entropy).hexdigest(), 16))[2:].zfill(256)[:4]
    bits = entropy_bits + checksum_bits
    return " ".join(WORDLIST[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))

def mnemonic_to_private_key(mnemonic):
    seed = hashlib.sha256(mnemonic.encode()).digest()
    return seed[:32]

def private_key_to_wif(private_key):
    extended_key = b'\x80' + private_key
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    return base58.b58encode(extended_key + checksum).decode()

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def public_key_to_address(public_key):
    sha256_pk = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pk)
    hashed_pk = ripemd160.digest()
    versioned_pk = b'\x00' + hashed_pk
    checksum = hashlib.sha256(hashlib.sha256(versioned_pk).digest()).digest()[:4]
    return base58.b58encode(versioned_pk + checksum).decode()

def check_balance(address):
    try:
        url = f"https://blockstream.info/api/address/{address}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            funded = data["chain_stats"]["funded_txo_sum"]
            spent = data["chain_stats"]["spent_txo_sum"]
            return (funded - spent) / 1e8
        else:
            return None
    except Exception:
        return None

# --- GUI Utility ---
def copy_to_clipboard(text):
    window.clipboard_clear()
    window.clipboard_append(text)
    status_label.config(text=f"Copied to clipboard: {text[:30]}{'...' if len(text) > 30 else ''}", fg="blue")
    window.after(3000, lambda: status_label.config(text=""))

def open_btc_explorer(address):
    webbrowser.open(f"https://blockstream.info/address/{address}")

def create_clickable_label(parent, text, row, column, wraplength=300):
    lbl = tk.Label(parent, text=text, font=("Consolas", 9), borderwidth=1, relief="solid", padx=5, pady=5, wraplength=wraplength, cursor="hand2")
    lbl.grid(row=row, column=column, sticky="nsew")
    lbl.bind("<Button-1>", lambda e: copy_to_clipboard(text))
    return lbl

def create_address_with_link(parent, address, row, column):
    frame = tk.Frame(parent, borderwidth=1, relief="solid", padx=3, pady=3)
    frame.grid(row=row, column=column, sticky="nsew")

    addr_lbl = tk.Label(frame, text=address, font=("Consolas", 9), fg="blue", cursor="hand2", wraplength=250)
    addr_lbl.pack(side="left", fill="x", expand=True)
    addr_lbl.bind("<Button-1>", lambda e: copy_to_clipboard(address))

    link_btn = tk.Button(frame, text="🔗", font=("Arial", 10), fg="darkblue", cursor="hand2", relief="flat", bd=0, command=lambda: open_btc_explorer(address))
    link_btn.pack(side="left", padx=5)

    return frame

# --- Wallet Generator (Threaded) ---
def background_wallet_search():
    global searching, wallet_found

    def update_ui(batch_results):
        global searching, wallet_found
        for widget in output_frame.winfo_children():
            widget.destroy()

        headers = ["Mnemonic (12 words)", "Legacy BTC Address", "WIF Private Key", "Balance"]
        for col, header in enumerate(headers):
            lbl = tk.Label(output_frame, text=header, font=("Segoe UI", 11, "bold"), borderwidth=1, relief="solid", padx=5, pady=5, bg="#e6e6e6")
            lbl.grid(row=0, column=col, sticky="nsew")

        for row, (mnemonic, address, wif, balance) in enumerate(batch_results, start=1):
            create_clickable_label(output_frame, mnemonic, row, 0, wraplength=400)
            create_address_with_link(output_frame, address, row, 1)
            create_clickable_label(output_frame, wif, row, 2, wraplength=250)

            balance_text = f"{balance:.8f} BTC" if balance is not None else "API Error"
            lbl_balance = tk.Label(output_frame, text=balance_text, font=("Consolas", 9), borderwidth=1, relief="solid", padx=5, pady=5)
            lbl_balance.grid(row=row, column=3, sticky="nsew")

            if balance and balance > 0:
                # Save wallet details to file
                with open("found_wallets.txt", "a") as f:
                    f.write("🔐 Wallet Found\n")
                    f.write(f"Time      : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Mnemonic  : {mnemonic}\n")
                    f.write(f"Address   : {address}\n")
                    f.write(f"WIF       : {wif}\n")
                    f.write(f"Balance   : {balance:.8f} BTC\n")
                    f.write("-" * 50 + "\n")

                status_label.config(text=f"💰 Found! Address: {address} | {balance_text}", fg="green")
                wallet_found = True
                stop_search()
                return

        for col in range(4):
            output_frame.grid_columnconfigure(col, weight=1)

        if searching:
            status_label.config(text="Searching next batch...", fg="black")
            threading.Thread(target=background_wallet_search).start()

    if not searching:
        return

    wallet_found = False
    batch_results = []
    batch_size = int(wallet_count_var.get())

    for _ in range(batch_size):
        if not searching:
            break
        mnemonic = generate_mnemonic()
        private_key = mnemonic_to_private_key(mnemonic)
        wif = private_key_to_wif(private_key)
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)
        balance = check_balance(address)
        batch_results.append((mnemonic, address, wif, balance))
        time.sleep(0.5)  # optional delay

    window.after(0, lambda: update_ui(batch_results))

# --- Control Functions ---
def start_search():
    global searching
    if searching:
        return
    searching = True
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")
    status_label.config(text="Starting search...", fg="black")
    threading.Thread(target=background_wallet_search).start()

def stop_search():
    global searching
    searching = False
    status_label.config(text="Search stopped by user.", fg="red")
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")

def toggle_dark_mode():
    global dark_mode
    dark_mode = not dark_mode
    bg = "#1e1e1e" if dark_mode else "#ffffff"
    fg = "#ffffff" if dark_mode else "#000000"
    window.configure(bg=bg)
    output_frame.configure(bg=bg)
    status_label.configure(bg=bg, fg=fg)
    for child in window.winfo_children():
        if isinstance(child, tk.Button) or isinstance(child, tk.Label):
            child.configure(bg=bg, fg=fg)

# --- GUI Setup ---
window = tk.Tk()
window.title("🟠 Bitcoin Wallet Generator - Threaded + UI Enhancements")
window.geometry("1150x550")

top_frame = tk.Frame(window)
top_frame.pack(pady=10)

start_btn = tk.Button(top_frame, text="▶ Start Auto Search", command=start_search, font=("Segoe UI", 11))
start_btn.grid(row=0, column=0, padx=5)

stop_btn = tk.Button(top_frame, text="■ Stop Search", command=stop_search, font=("Segoe UI", 11), state="disabled")
stop_btn.grid(row=0, column=1, padx=5)

wallet_count_var = tk.StringVar(value="5")
wallet_count_entry = tk.Entry(top_frame, textvariable=wallet_count_var, font=("Segoe UI", 11), width=5, justify="center")
wallet_count_entry.grid(row=0, column=2, padx=5)
tk.Label(top_frame, text="Wallets/Batch", font=("Segoe UI", 10)).grid(row=0, column=3, padx=5)

dark_toggle_btn = tk.Button(top_frame, text="🌙 Toggle Dark Mode", command=toggle_dark_mode, font=("Segoe UI", 11))
dark_toggle_btn.grid(row=0, column=4, padx=5)

# Scrollable output
output_container = tk.Frame(window)
output_container.pack(fill="both", expand=True, padx=10, pady=5)

canvas = tk.Canvas(output_container)
scrollbar = tk.Scrollbar(output_container, orient="vertical", command=canvas.yview)
output_frame = tk.Frame(canvas)

output_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas.create_window((0, 0), window=output_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

status_label = tk.Label(window, text="", font=("Segoe UI", 10))
status_label.pack(pady=5)

window.mainloop()
