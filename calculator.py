import os
import time
from functools import wraps
import gspread
from google.oauth2.service_account import Credentials

acc_size = float('2000')

# ========================
# Robust credentials loading
# ========================
script_dir = os.path.dirname(os.path.abspath(__file__))
creds_path = os.path.join(script_dir, "creds.json")

creds = Credentials.from_service_account_file(
    creds_path,
    scopes=[
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
    ]
)

print("Credentials loaded from:", creds_path)


# Connect to Google Sheets

client = gspread.authorize(creds)
spreadsheet = client.open("Calc")  # NOT "Calc.xlsx"

# ========================
# Rate limiter (max 1 req/sec)
# ========================
_last_request_time = 0

def rate_limited(min_interval=1.0):
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

# ========================
# Hybrid helpers
# ========================
@rate_limited(1.0)
def read_range(sheet_name, cell_range):
    ws = spreadsheet.worksheet(sheet_name)
    return ws.get(cell_range)

@rate_limited(1.0)
def write_range(sheet_name, cell_range, values):
    ws = spreadsheet.worksheet(sheet_name)
    ws.update(values=values, range_name=cell_range)

def read(sheet_name, cell):
    return read_range(sheet_name, cell)[0][0]

def read1(sheet_name, cell):
    return read(sheet_name, cell)

def write(sheet_name, cell, value):
    write_range(sheet_name, cell, [[value]])
    print(f"Wrote '{value}' to {sheet_name}!{cell}")

# ========================
# TCL calc logic
# ========================
def tcl_calc(price1: float, price2: float, symbol: str, type: str):
    sheet = "TCL Calc (10% Risk)"   # tab name in Google Sheets

    if price1 > price2:
        # Uptrend
        diff = price2 - price1
        L1 = price2 - diff * 0.618
        L2 = price2 - diff * 0.372
        L3 = price2 - diff * 0.17
        TP1 = price2 - diff * 1.272
        SL = price2 - diff * -0.05
        side = "Buy"
        write(sheet, "B5", "LONG")
    else:
        # Downtrend
        diff = price1 - price2
        L1 = price2 + diff * 0.618
        L2 = price2 + diff * 0.372
        L3 = price2 + diff * 0.17
        TP1 = price2 + diff * 1.272
        SL = price2 + diff * -0.05
        side = "Sell"
        write(sheet, "B5", "SHORT")

    # Batch write setup levels
    write_range(sheet, "C6:C8", [[L1], [TP1], [SL]])
    write_range(sheet, "C13:C14", [[L2], [L3]])

    # Batch read block (D6:E14)
    values = read_range(sheet, "D6:E14")
    qty1 = float(values[0][0])   # D6
    qty2 = float(values[7][0])   # D13
    qty3 = float(values[8][0])   # D14
    tp2  = float(values[7][1])   # E13
    tp3  = float(values[8][1])   # E14
    margin_status = str(values[3][0])  # D9

    # Position sizing
    position_size = (qty1 * L1) + (qty2 * L2) + (qty3 * L3)
    leverage_input = round(position_size * 1.1/ acc_size)
    write(sheet, "C9", leverage_input)
    


    print("Leverage accepted")

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

    if type == "tcl1":
        tpsl_dict = {
            "tp1": TP1,
            "sl1": SL,
            "tp2": tp2,
            "sl2": SL,
            "tp3": tp3,
            "sl3": SL,
            "symbol": symbol
        }
    if type == 'tcl2':
        tpsl_dict = {
            "tp1": TP1,
            "sl1": SL,
            "tp2": TP1,
            "sl2": SL,
            "tp3": tp3,
            "sl3": SL,
            "symbol": symbol
        }
    if type == 'tcl3':
        tpsl_dict = {
            "tp1": TP1,
            "sl1": SL,
            "tp2": TP1,
            "sl2": SL,
            "tp3": tp2,
            "sl3": SL,
            "symbol": symbol
        }
    if type == 'tcl4':
        tpsl_dict = {
            "tp1": TP1,
            "sl1": SL,
            "tp2": TP1,
            "sl2": SL,
            "tp3": TP1,
            "sl3": SL,
            "symbol": symbol
        }

    print(order_dict)
    print(tpsl_dict)
    return order_dict, tpsl_dict

