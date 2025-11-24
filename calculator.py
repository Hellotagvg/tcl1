#!/usr/bin/env python3
"""
tcl_calc_termux_safe.py

Termux-friendly, robust Google Sheets service-account wrapper + your TCL calc logic.
- Auto-fixes creds.json private_key formatting (\n literal -> real newlines)
- Backs up creds.json to creds.json.bak before modifying
- NTP check via ntplib and best-effort system time set
- Credential refresh to detect Invalid JWT Signature early
- gspread wrappers with rate-limit and retry/backoff
- Keeps your tcl_calc logic and returns order/tpsl dicts

Requirements:
  pip install gspread google-auth ntplib google-auth-httplib2 google-auth-oauthlib
"""

import os
import time
import json
import re
import shutil
import logging
import subprocess
from functools import wraps
from typing import Any, Callable, List, Tuple

# third-party
import ntplib
import gspread
from google.oauth2.service_account import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from gspread.exceptions import APIError

# --------------------------
# Configuration
# --------------------------
CREDS_FILENAME = "creds.json"
SPREADSHEET_NAME = "Calc"
REQUIRED_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"  # optional but left for parity with your original
]
RATE_LIMIT_SECONDS = 1.0
MAX_RETRIES = 5
BACKOFF_BASE = 0.5
NTP_POOL = "pool.ntp.org"
MAX_ALLOWED_SKEW = 120  # seconds
acc_size = float("2000")  # from your original script

# --------------------------
# Logging
# --------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("tcl_termux")

# --------------------------
# PEM/creds fixer
# --------------------------
def _wrap_base64(s: str, width: int = 64) -> str:
    return "\n".join(s[i:i+width] for i in range(0, len(s), width))

def _is_pem_valid(pem: str) -> bool:
    if not isinstance(pem, str):
        return False
    if "-----BEGIN PRIVATE KEY-----" not in pem or "-----END PRIVATE KEY-----" not in pem:
        return False
    inner = re.sub(r"-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+", "", pem)
    return len(inner) > 100

def ensure_service_account_pem(creds_path: str) -> Tuple[bool, str]:
    """
    Ensure creds_path has a properly formatted private_key with real newlines.
    Backs up original to creds_path + ".bak" before overwriting.
    Returns (ok, message).
    """
    if not os.path.isfile(creds_path):
        return False, f"Credentials file not found: {creds_path}"

    try:
        with open(creds_path, "r", encoding="utf-8") as f:
            raw = f.read()
        data = json.loads(raw)
    except Exception as e:
        return False, f"Failed to read/parse JSON: {e}"

    if "private_key" not in data:
        return False, "JSON missing 'private_key' field."

    orig_key = data["private_key"]

    # Already valid?
    if _is_pem_valid(orig_key) and "\n" in orig_key and "\\n" not in orig_key:
        return True, "private_key already valid."

    # backup
    bak_path = creds_path + ".bak"
    try:
        if not os.path.exists(bak_path):
            shutil.copy2(creds_path, bak_path)
            log.info("Backup created: %s", bak_path)
        else:
            log.info("Backup already exists: %s", bak_path)
    except Exception as e:
        return False, f"Failed to create backup: {e}"

    fixed = orig_key

    # Replace escaped newlines with real newlines
    if "\\r\\n" in fixed or "\\n" in fixed:
        fixed = fixed.replace("\\r\\n", "\n").replace("\\n", "\n")
        log.info("Replaced escaped newline sequences (\\n / \\r\\n).")

    # Remove stray $ at EOL (some viewers show $; be conservative)
    if "$" in fixed:
        fixed = re.sub(r"\$\s*$", "", fixed, flags=re.MULTILINE)
        log.info("Removed stray $ end-of-line markers if present.")

    # If still not valid, try to rebuild from single-line base64
    if not _is_pem_valid(fixed):
        m = re.search(r"-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----", fixed, flags=re.DOTALL)
        if m:
            inner = m.group(1)
            inner_clean = re.sub(r"\\n|\s+", "", inner)
            if len(inner_clean) > 100:
                fixed = "-----BEGIN PRIVATE KEY-----\n" + _wrap_base64(inner_clean, 64) + "\n-----END PRIVATE KEY-----\n"
                log.info("Rebuilt PEM by wrapping inner base64.")
        else:
            # maybe only base64 content
            only = re.sub(r"\s+", "", fixed)
            if len(only) > 300:
                fixed = "-----BEGIN PRIVATE KEY-----\n" + _wrap_base64(only, 64) + "\n-----END PRIVATE KEY-----\n"
                log.info("Added PEM markers and wrapped base64 (single-line input).")

    if not _is_pem_valid(fixed):
        return False, "Unable to construct valid PEM from private_key; backup at " + bak_path

    # Validate by creating credentials from info and refreshing
    data_fixed = dict(data)
    data_fixed["private_key"] = fixed
    try:
        creds = Credentials.from_service_account_info(data_fixed, scopes=[REQUIRED_SCOPES[0]])
        creds.refresh(Request())
        log.info("Credentials validated after fixing private_key; token expiry: %s", getattr(creds, "expiry", None))
    except RefreshError as re:
        return False, f"Credentials refresh failed after fix: {re}. Backup at {bak_path}"
    except Exception as e:
        return False, f"Unexpected error validating credentials: {e}"

    # Write fixed data to file atomically
    try:
        tmp = creds_path + ".tmp"
        data["private_key"] = fixed
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, creds_path)
        log.info("Wrote fixed credentials to %s (orig backed up at %s)", creds_path, bak_path)
        return True, "Credentials fixed and validated."
    except Exception as e:
        # try restore
        try:
            if os.path.exists(bak_path):
                shutil.copy2(bak_path, creds_path)
        except Exception:
            pass
        return False, f"Failed to write fixed creds: {e}"

# --------------------------
# NTP / Time helpers
# --------------------------
def check_ntp_time(ntp_pool: str = NTP_POOL, timeout: int = 5) -> Tuple[bool, float, float]:
    try:
        client = ntplib.NTPClient()
        response = client.request(ntp_pool, version=3, timeout=timeout)
        ntp_time = response.tx_time
        local = time.time()
        skew = abs(local - ntp_time)
        log.info("NTP time: %s | Local time: %s | Skew: %.1f s", time.ctime(ntp_time), time.ctime(local), skew)
        return (skew <= MAX_ALLOWED_SKEW, ntp_time, local)
    except Exception as e:
        log.warning("Failed to query NTP (%s): %s", ntp_pool, e)
        return (False, 0.0, time.time())

def attempt_set_system_time(ntp_time: float) -> bool:
    try:
        ts = time.gmtime(ntp_time)
        formatted = time.strftime("%Y-%m-%d %H:%M:%S", ts)
        log.info("Attempting to set system time to %s (may require root)", formatted)
        result = subprocess.run(["date", "-s", formatted], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            log.info("System time set successfully.")
            return True
        else:
            log.warning("Failed to set system time. stdout=%s stderr=%s", result.stdout, result.stderr)
            return False
    except Exception as e:
        log.warning("Exception while setting system time: %s", e)
        return False

# --------------------------
# Retry and rate-limiter utilities
# --------------------------
def retry_on_exceptions(max_retries: int = MAX_RETRIES, exceptions: tuple = (Exception,)):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt > max_retries:
                        log.exception("Max retries reached for %s", func.__name__)
                        raise
                    backoff = BACKOFF_BASE * (2 ** (attempt - 1))
                    log.warning("Exception in %s: %s; retrying in %.1f s (attempt %d/%d)", func.__name__, e, backoff, attempt, max_retries)
                    time.sleep(backoff)
        return wrapper
    return decorator

_last_request_time = 0.0

def rate_limited(min_interval: float = RATE_LIMIT_SECONDS):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            global _last_request_time
            now = time.time()
            elapsed = now - _last_request_time
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            result = func(*args, **kwargs)
            _last_request_time = time.time()
            return result
        return wrapper
    return decorator

# --------------------------
# Safe gspread wrapper
# --------------------------
class SafeSheets:
    def __init__(self, client: gspread.Client, spreadsheet_name: str):
        self.client = client
        self.spreadsheet_name = spreadsheet_name
        self.spreadsheet = self.open_spreadsheet()

    @retry_on_exceptions(exceptions=(APIError, gspread.exceptions.GSpreadException))
    def open_spreadsheet(self):
        log.info("Opening spreadsheet: %s", self.spreadsheet_name)
        return self.client.open(self.spreadsheet_name)

    @rate_limited()
    @retry_on_exceptions(exceptions=(APIError, gspread.exceptions.GSpreadException))
    def read_range(self, sheet_name: str, cell_range: str) -> List[List[Any]]:
        ws = self.spreadsheet.worksheet(sheet_name)
        return ws.get(cell_range)

    @rate_limited()
    @retry_on_exceptions(exceptions=(APIError, gspread.exceptions.GSpreadException))
    def write_range(self, sheet_name: str, cell_range: str, values: List[List[Any]]):
        ws = self.spreadsheet.worksheet(sheet_name)
        ws.update(values=values, range_name=cell_range)

    def read(self, sheet_name: str, cell: str) -> Any:
        val = self.read_range(sheet_name, cell)
        return val[0][0] if val and len(val) and len(val[0]) else None

    def write(self, sheet_name: str, cell: str, value: Any):
        self.write_range(sheet_name, cell, [[value]])
        log.info("Wrote '%s' to %s!%s", value, sheet_name, cell)

# --------------------------
# Your tcl_calc (kept mostly identical)
# --------------------------
def tcl_calc(sheets: SafeSheets, price1: float, price2: float, symbol: str, type_: str):
    sheet = "TCL Calc (10% Risk)"   # tab name in Google Sheets

    try:
        if price1 > price2:
            diff = price2 - price1
            L1 = price2 - diff * 0.618
            L2 = price2 - diff * 0.372
            L3 = price2 - diff * 0.17
            TP1 = price2 - diff * 1.272
            SL = price2 - diff * -0.05
            side = "Buy"
            sheets.write(sheet, "B5", "LONG")
        else:
            diff = price1 - price2
            L1 = price2 + diff * 0.618
            L2 = price2 + diff * 0.372
            L3 = price2 + diff * 0.17
            TP1 = price2 + diff * 1.272
            SL = price2 + diff * -0.05
            side = "Sell"
            sheets.write(sheet, "B5", "SHORT")

        sheets.write_range(sheet, "C6:C8", [[L1], [TP1], [SL]])
        sheets.write_range(sheet, "C13:C14", [[L2], [L3]])

        values = sheets.read_range(sheet, "D6:E14")
        # defensive positions: check shapes
        if not values or len(values) < 9:
            raise RuntimeError("Unexpected range shape from sheet (expected D6:E14 block).")

        qty1 = float(values[0][0])   # D6
        qty2 = float(values[7][0])   # D13
        qty3 = float(values[8][0])   # D14
        tp2  = float(values[7][1])   # E13
        tp3  = float(values[8][1])   # E14

        position_size = (qty1 * L1) + (qty2 * L2) + (qty3 * L3)
        leverage_input = round(position_size * 1.1 / acc_size)
        sheets.write(sheet, "C9", leverage_input)

        log.info("Leverage accepted: %s", leverage_input)

        order_dict = {
            "limit1": L1, "limit2": L2, "limit3": L3,
            "qty1": qty1, "qty2": qty2, "qty3": qty3,
            "coin": symbol, "leverage": leverage_input, "side": side
        }

        if type_ == "tcl1":
            tpsl_dict = {"tp1": TP1, "sl1": SL, "tp2": tp2, "sl2": SL, "tp3": tp3, "sl3": SL, "symbol": symbol}
        elif type_ == "tcl2":
            tpsl_dict = {"tp1": TP1, "sl1": SL, "tp2": TP1, "sl2": SL, "tp3": tp3, "sl3": SL, "symbol": symbol}
        elif type_ == "tcl3":
            tpsl_dict = {"tp1": TP1, "sl1": SL, "tp2": TP1, "sl2": SL, "tp3": tp2, "sl3": SL, "symbol": symbol}
        elif type_ == "tcl4":
            tpsl_dict = {"tp1": TP1, "sl1": SL, "tp2": TP1, "sl2": SL, "tp3": TP1, "sl3": SL, "symbol": symbol}
        else:
            raise ValueError("Unknown type_: " + str(type_))

        log.info("order: %s", order_dict)
        log.info("tpsl: %s", tpsl_dict)
        return order_dict, tpsl_dict

    except Exception:
        log.exception("Error during tcl_calc")
        raise

# --------------------------
# Main
# --------------------------
def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    creds_path = os.path.join(script_dir, CREDS_FILENAME)

    # 1) NTP check
    ok, ntp_time, local_time = check_ntp_time()
    if not ok:
        log.warning("Time skew > %d s or NTP failed. Attempting a best-effort set.", MAX_ALLOWED_SKEW)
        if attempt_set_system_time(ntp_time):
            log.info("System time set; continuing.")
        else:
            log.warning("Could not set system time automatically. If running on Termux, try: 'pkg install ntpdate' then 'ntpdate -s pool.ntp.org' or enable Android automatic time.")

    # 2) Fix creds.json if necessary
    ok, msg = ensure_service_account_pem(creds_path)
    if not ok:
        log.error("Credential fix failed: %s", msg)
        return 1
    log.info("Credential check/fix: %s", msg)

    # 3) Load credentials and try refresh (final validation)
    try:
        creds = Credentials.from_service_account_file(creds_path, scopes=REQUIRED_SCOPES)
        # refresh to ensure JWT/signature ok
        creds.refresh(Request())
        log.info("Credentials loaded and refreshed; expiry=%s", getattr(creds, "expiry", None))
    except Exception as e:
        log.exception("Failed to load/refresh credentials: %s", e)
        return 1

    # 4) Authorize gspread
    try:
        client = gspread.authorize(creds)
    except Exception as e:
        log.exception("Failed to authorize gspread: %s", e)
        return 1

    # 5) Open spreadsheet and simple test
    try:
        sheets = SafeSheets(client, SPREADSHEET_NAME)
        # quick read test: first worksheet A1
        try:
            first_ws_title = sheets.spreadsheet.worksheets()[0].title
            val = sheets.read(first_ws_title, "A1")
            log.info("Test read successful. %s!A1 = %s", first_ws_title, val)
        except Exception as e:
            log.warning("Could not read A1: %s", e)
            log.info("Ensure the spreadsheet '%s' is shared with the service account email from creds.json.", SPREADSHEET_NAME)
            return 1
    except Exception as e:
        log.exception("Error opening spreadsheet: %s", e)
        return 1

    # 6) Example run of tcl_calc (replace with your real inputs)
    try:
        order, tpsl = tcl_calc(sheets, price1=100.0, price2=90.0, symbol="BTCUSDT", type_="tcl1")
        log.info("tcl_calc completed successfully.")
    except Exception as e:
        log.error("tcl_calc failed: %s", e)

    return 0

if __name__ == "__main__":
    exit(main())
