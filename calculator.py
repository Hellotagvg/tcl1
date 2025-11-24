#!/usr/bin/env python3
"""
Robust Termux-friendly Google Sheets + service account script.

Features:
 - ntplib-based NTP check and attempt to set the system clock (requires root).
 - Validates service account JSON and private_key formatting.
 - Attempts to refresh credentials immediately to detect JWT/signature issues.
 - Exponential backoff + retries for gspread calls.
 - Rate limiter (1 req/sec).
 - Clear, actionable error messages for Termux/Android.
"""

import os
import time
import json
import re
import logging
import subprocess
import socket
from functools import wraps
from typing import Any, Callable, List, Tuple

# third-party libs (install or pip upgrade if necessary)
# pip install gspread google-auth ntplib google-auth-httplib2 google-auth-oauthlib
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
    # "https://www.googleapis.com/auth/drive",  # enable only if you need Drive access
]
RATE_LIMIT_SECONDS = 1.0
MAX_RETRIES = 5
BACKOFF_BASE = 0.5  # seconds
NTP_POOL = "pool.ntp.org"
MAX_ALLOWED_SKEW = 120  # seconds; > this we consider problematic

# Risk/account config from your original script
acc_size = float("2000")

# --------------------------
# Logging
# --------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("tcl_safe")

# --------------------------
# Helpers: time sync & checks
# --------------------------
def is_running_on_android() -> bool:
    return "ANDROID_ROOT" in os.environ or "com.termux" in os.environ.get("TERM", "")

def check_ntp_time(ntp_pool: str = NTP_POOL, timeout: int = 5) -> Tuple[bool, float, float]:
    """
    Query NTP server and return (ok, ntp_time, local_time).
    ok == True if skew <= MAX_ALLOWED_SKEW.
    """
    try:
        client = ntplib.NTPClient()
        response = client.request(ntp_pool, version=3, timeout=timeout)
        ntp_time = response.tx_time
        local_time = time.time()
        skew = abs(local_time - ntp_time)
        log.info("NTP time: %s | Local time: %s | Skew: %.1f s", time.ctime(ntp_time), time.ctime(local_time), skew)
        return (skew <= MAX_ALLOWED_SKEW, ntp_time, local_time)
    except Exception as e:
        log.warning("Failed to query NTP server (%s): %s", ntp_pool, e)
        return (False, 0.0, time.time())

def attempt_set_system_time(ntp_time: float) -> bool:
    """
    Try to set system time (requires root). Returns True if succeeded.
    On Android/Termux this will usually fail without root; we still try.
    """
    try:
        # Format: YYYY-MM-DD HH:MM:SS
        ts = time.gmtime(ntp_time)
        formatted = time.strftime("%Y-%m-%d %H:%M:%S", ts)
        log.info("Attempting to set system time to %s (may require root)", formatted)
        # 'date -s' format for many systems; may fail on Android if not rooted.
        result = subprocess.run(["date", "-s", formatted], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            log.info("System time set successfully.")
            return True
        else:
            log.warning("Failed to set system time. stdout=%s stderr=%s", result.stdout, result.stderr)
            return False
    except Exception as e:
        log.warning("Exception while attempting to set system time: %s", e)
        return False

# --------------------------
# Credential loading & validation
# --------------------------
def validate_service_account_json(data: dict) -> None:
    required_keys = {"type", "private_key", "client_email", "token_uri", "project_id"}
    missing = required_keys - set(data.keys())
    if missing:
        raise ValueError(f"Service account JSON is missing required keys: {missing}")

    if data.get("type") != "service_account":
        raise ValueError("JSON 'type' is not 'service_account'")

    pk = data.get("private_key", "")
    if not isinstance(pk, str) or "BEGIN PRIVATE KEY" not in pk or "END PRIVATE KEY" not in pk:
        raise ValueError("private_key appears malformed or missing BEGIN/END markers")

    # sanity-check: ensure private_key contains multiple line breaks and base64-looking content
    inner = re.sub(r"-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+", "", pk)
    if len(inner) < 100:
        raise ValueError("private_key seems too short; likely corrupted")

def load_credentials_safe(creds_path: str, scopes: List[str]) -> Credentials:
    """
    Loads and validates service account credentials. Also attempts immediate refresh
    to catch JWT signing or auth problems early.
    """
    if not os.path.isfile(creds_path):
        raise FileNotFoundError(f"Credentials file not found at: {creds_path}")

    # read JSON raw (don't alter line endings)
    with open(creds_path, "r", encoding="utf-8") as f:
        raw = f.read()

    try:
        data = json.loads(raw)
    except Exception as e:
        raise ValueError(f"Failed to parse JSON from {creds_path}: {e}")

    # validate basic structure
    validate_service_account_json(data)

    # create credentials using google auth helper
    try:
        creds = Credentials.from_service_account_file(creds_path, scopes=scopes)
    except Exception as e:
        raise RuntimeError(f"Failed to create Credentials from file: {e}")

    # attempt refresh (exchanges JWT for OAuth token) to catch signature errors now
    try:
        request = Request()
        creds.refresh(request)  # may raise RefreshError
        log.info("Credentials refreshed; token expiry at %s", getattr(creds, "expiry", "unknown"))
    except RefreshError as re:
        # Common causes: clock skew, corrupted private_key, revoked key
        raise RuntimeError(
            "Failed to refresh credentials (JWT/token error). Possible causes: "
            "system clock skew, corrupted private_key, revoked key. "
            f"Underlying error: {re}"
        )
    except Exception as e:
        raise RuntimeError(f"Unexpected error while refreshing credentials: {e}")

    return creds

# --------------------------
# Retry decorator for gspread ops
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

# --------------------------
# Rate limiter (1 req/sec)
# --------------------------
_last_request_time = 0.0

def rate_limited(min_interval: float = RATE_LIMIT_SECONDS):
    def decorator(func):
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
# Safe gspread wrappers
# --------------------------
class SafeSheets:
    def __init__(self, client: gspread.Client, spreadsheet_name: str):
        self.client = client
        self.spreadsheet_name = spreadsheet_name
        self.spreadsheet = None
        self.open_spreadsheet()

    @retry_on_exceptions(exceptions=(APIError, socket.error, gspread.exceptions.GSpreadException))
    def open_spreadsheet(self):
        log.info("Opening spreadsheet: %s", self.spreadsheet_name)
        self.spreadsheet = self.client.open(self.spreadsheet_name)
        return self.spreadsheet

    @rate_limited()
    @retry_on_exceptions(exceptions=(APIError, socket.error, gspread.exceptions.GSpreadException))
    def read_range(self, sheet_name: str, cell_range: str) -> List[List[Any]]:
        ws = self.spreadsheet.worksheet(sheet_name)
        return ws.get(cell_range)

    @rate_limited()
    @retry_on_exceptions(exceptions=(APIError, socket.error, gspread.exceptions.GSpreadException))
    def write_range(self, sheet_name: str, cell_range: str, values: List[List[Any]]):
        ws = self.spreadsheet.worksheet(sheet_name)
        # gspread uses update(range_name=..., values=...)
        ws.update(values=values, range_name=cell_range)

    def read(self, sheet_name: str, cell: str) -> Any:
        val = self.read_range(sheet_name, cell)
        return val[0][0] if (val and len(val) and len(val[0])) else None

    def write(self, sheet_name: str, cell: str, value: Any):
        self.write_range(sheet_name, cell, [[value]])
        log.info("Wrote '%s' to %s!%s", value, sheet_name, cell)

# --------------------------
# Your TCL calc logic (kept as-is; slight safety checks)
# --------------------------
def tcl_calc(sheets: SafeSheets, price1: float, price2: float, symbol: str, type_: str):
    sheet = "TCL Calc (10% Risk)"   # tab name in Google Sheets

    # Defensive conversions & presence checks could be added here
    try:
        if price1 > price2:
            # Uptrend
            diff = price2 - price1
            L1 = price2 - diff * 0.618
            L2 = price2 - diff * 0.372
            L3 = price2 - diff * 0.17
            TP1 = price2 - diff * 1.272
            SL = price2 - diff * -0.05
            side = "Buy"
            sheets.write(sheet, "B5", "LONG")
        else:
            # Downtrend
            diff = price1 - price2
            L1 = price2 + diff * 0.618
            L2 = price2 + diff * 0.372
            L3 = price2 + diff * 0.17
            TP1 = price2 + diff * 1.272
            SL = price2 + diff * -0.05
            side = "Sell"
            sheets.write(sheet, "B5", "SHORT")

        # Batch write setup levels
        sheets.write_range(sheet, "C6:C8", [[L1], [TP1], [SL]])
        sheets.write_range(sheet, "C13:C14", [[L2], [L3]])

        # Batch read block (D6:E14)
        values = sheets.read_range(sheet, "D6:E14")
        qty1 = float(values[0][0])   # D6
        qty2 = float(values[7][0])   # D13
        qty3 = float(values[8][0])   # D14
        tp2  = float(values[7][1])   # E13
        tp3  = float(values[8][1])   # E14
        margin_status = str(values[3][0])  # D9

        # Position sizing
        position_size = (qty1 * L1) + (qty2 * L2) + (qty3 * L3)
        leverage_input = round(position_size * 1.1 / acc_size)
        sheets.write(sheet, "C9", leverage_input)

        log.info("Leverage accepted: %s", leverage_input)

        order_dict = {
            "limit1": L1,
            "limit2": L2,
            "limit3": L3,
            "qty1": qty1,
            "qty2": qty2,
            "qty3": qty3,
            "coin": symbol,
            "leverage": leverage_input,
            "side": side
        }

        # choose tpsl layout same as your original script
        if type_ == "tcl1":
            tpsl_dict = {
                "tp1": TP1,
                "sl1": SL,
                "tp2": tp2,
                "sl2": SL,
                "tp3": tp3,
                "sl3": SL,
                "symbol": symbol
            }
        elif type_ == 'tcl2':
            tpsl_dict = {
                "tp1": TP1,
                "sl1": SL,
                "tp2": TP1,
                "sl2": SL,
                "tp3": tp3,
                "sl3": SL,
                "symbol": symbol
            }
        elif type_ == 'tcl3':
            tpsl_dict = {
                "tp1": TP1,
                "sl1": SL,
                "tp2": TP1,
                "sl2": SL,
                "tp3": tp2,
                "sl3": SL,
                "symbol": symbol
            }
        elif type_ == 'tcl4':
            tpsl_dict = {
                "tp1": TP1,
                "sl1": SL,
                "tp2": TP1,
                "sl2": SL,
                "tp3": TP1,
                "sl3": SL,
                "symbol": symbol
            }
        else:
            raise ValueError("Unknown type_: " + str(type_))

        log.info("order: %s", order_dict)
        log.info("tpsl: %s", tpsl_dict)
        return order_dict, tpsl_dict

    except Exception:
        log.exception("Error during tcl_calc")
        raise

# --------------------------
# Main: coordinate checks and startup
# --------------------------
def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    creds_path = os.path.join(script_dir, CREDS_FILENAME)

    # 1) NTP check
    ok, ntp_time, local_time = check_ntp_time()
    if not ok:
        log.warning("Time skew is larger than %d seconds. Many Google auth errors are caused by this.", MAX_ALLOWED_SKEW)
        # Try to set system time (likely requires root). If it fails, instruct the user.
        if attempt_set_system_time(ntp_time):
            log.info("System time updated; continuing.")
        else:
            log.warning("Could not set system time automatically. On Termux/Android try: "
                        "'pkg install ntpdate' then 'ntpdate -s pool.ntp.org' (may require root). "
                        "Alternatively sync your Android device time via Settings -> Date & time -> Set automatically.")
            # we don't immediately exit; we'll still attempt auth to produce a clearer error if needed

    # 2) Load credentials and validate (this will also attempt refresh)
    try:
        creds = load_credentials_safe(creds_path, REQUIRED_SCOPES)
        log.info("Credentials loaded and validated from: %s", creds_path)
    except Exception as e:
        log.error("Credentials failure: %s", e)
        return 1

    # 3) Authorize gspread and test basic access
    try:
        client = gspread.authorize(creds)
    except Exception as e:
        log.error("Failed to authorize gspread client: %s", e)
        return 1

    try:
        sheets = SafeSheets(client, SPREADSHEET_NAME)
        # quick read test: read A1 of first worksheet safely
        try:
            val = sheets.read(sheets.spreadsheet.worksheets()[0].title, "A1")
            log.info("Test read successful. A1 = %s", val)
        except Exception as e:
            log.warning("Could not read A1: %s", e)
            # still may have permission problems or sheet not shared
            log.info("Make sure the spreadsheet '%s' is shared with the service account email in the JSON (client_email).", SPREADSHEET_NAME)
            return 1

    except Exception as e:
        log.exception("Error opening spreadsheet: %s", e)
        return 1

    # If we reach here, core systems are OK. You can call tcl_calc as needed.
    # Example usage (replace with real values):
    try:
        order, tpsl = tcl_calc(sheets, price1=100.0, price2=90.0, symbol="BTCUSDT", type_="tcl1")
        log.info("tcl_calc returned successfully")
    except Exception as e:
        log.error("tcl_calc failed: %s", e)

    return 0

if __name__ == "__main__":
    exit(main())
