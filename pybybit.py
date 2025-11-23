#!/usr/bin/env python3
"""
trade_tcl_ntp_safe_v2.py

Multi-account Bybit trading helper:
- NTP / Bybit server time patch to align HMAC timestamps
- Safe to call trade_tcl(...) repeatedly in same process
- Single global "cancel" listener: type "cancel" to stop the most recent run
- Selective timeout cleanup: only cancels orders placed by this run and only closes positions
  that this run created (tracked via active_position_flag)
- Uses manual signed POST for critical actions (avoids pybit POST quirks)

Requirements:
    pip install ntplib requests pybit
"""
from __future__ import annotations
import threading
import time
import uuid
import queue
import requests
import contextlib
import hmac
import hashlib
import json
import ntplib
import traceback
import gc
from typing import Dict, Any, Optional, Set, List

from pybit.unified_trading import HTTP

# ---------------------- CONFIG ----------------------
RECV_WINDOW_MS = 600000  # 10 minutes
NTP_SERVERS = ["pool.ntp.org", "time.google.com", "time.cloudflare.com"]

# ---------------------- Global runtime/shared state ----------------------
# Rate limiter map (cleared each run)
_last_request_time: Dict[str, float] = {}
_state_lock = threading.RLock()

# Global single-line input listener (only one thread for the entire process).
# When user types "cancel", the listener will signal the most recently registered run.
_global_input_listener_started = False
_global_input_listener_lock = threading.Lock()
# list of active run cancel Events in registration order (append on start, pop on cleanup)
_global_active_run_events: List[threading.Event] = []


# ---------------------- Time helpers ----------------------
def _fetch_ntp_time_ms(servers=None, timeout=5) -> Optional[int]:
    if servers is None:
        servers = NTP_SERVERS
    client = ntplib.NTPClient()
    for s in servers:
        try:
            resp = client.request(s, version=3, timeout=timeout)
            return int(resp.tx_time * 1000)
        except Exception:
            continue
    return None


def _fetch_bybit_server_time_ms(demo=True, timeout=5) -> Optional[int]:
    candidates = []
    if demo:
        candidates += [
            "https://api-demo.bybit.com/v5/public/time",
            "https://api-demo.bybit.com/v2/public/time",
        ]
    candidates += [
        "https://api.bybit.com/v5/public/time",
        "https://api.bybit.com/v2/public/time",
    ]
    for url in candidates:
        try:
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            j = r.json()
            server_ts = None
            if isinstance(j, dict):
                if "time" in j:
                    server_ts = int(j["time"])
                elif "time_now" in j:
                    try:
                        server_ts = int(float(j["time_now"]) * 1000)
                    except Exception:
                        server_ts = int(j["time_now"])
                elif "result" in j and isinstance(j["result"], dict) and "time" in j["result"]:
                    server_ts = int(j["result"]["time"])
            if server_ts is not None:
                if server_ts < 10**12:
                    server_ts = int(server_ts * 1000)
                return server_ts
        except Exception:
            continue
    return None


@contextlib.contextmanager
def use_ntp_time_patch(verbose=True, ntp_servers=None, demo_fallback=True):
    """
    Patch time.time() and time.time_ns() so HMAC timestamps use authoritative NTP/Bybit time.
    Yields True if patched; False if no patch applied.
    Restores originals on exit.
    """
    ntp_ts = _fetch_ntp_time_ms(servers=ntp_servers or NTP_SERVERS)
    source = "NTP"
    server_ts = ntp_ts
    if server_ts is None and demo_fallback:
        server_ts = _fetch_bybit_server_time_ms(demo=True)
        source = "Bybit"

    if server_ts is None:
        if verbose:
            print("[time-patch] WARNING: could not fetch NTP/Bybit time; not patching time()")
        yield False
        return

    local_ts = int(time.time() * 1000)
    offset_ms = server_ts - local_ts
    offset_s = offset_ms / 1000.0

    if verbose:
        print(f"[time-patch] source={source} server_ms={server_ts}, local_ms={local_ts}, offset_ms={offset_ms}")

    orig_time = time.time
    orig_time_ns = getattr(time, "time_ns", None)

    def patched_time():
        return orig_time() + offset_s

    def patched_time_ns():
        return int((orig_time() + offset_s) * 1_000_000_000)

    # Apply patch
    time.time = patched_time
    if orig_time_ns is not None:
        time.time_ns = patched_time_ns

    try:
        yield True
    finally:
        # Restore originals
        time.time = orig_time
        if orig_time_ns is not None:
            time.time_ns = orig_time_ns
        if verbose:
            print("[time-patch] restored original time() and time_ns()")


# ---------------------- Global input listener ----------------------
def _start_global_input_listener_once():
    global _global_input_listener_started
    with _global_input_listener_lock:
        if _global_input_listener_started:
            return
        _global_input_listener_started = True

    def _listener():
        # runs forever; when user types "cancel" it signals the most recent active run
        print("[input-listener] started. Type 'cancel' to stop the most recent run.")
        while True:
            try:
                line = input().strip().lower()
            except Exception:
                # input closed or environment not interactive
                return
            if line == "cancel":
                with _global_input_listener_lock:
                    if _global_active_run_events:
                        last_evt = _global_active_run_events[-1]
                        last_evt.set()
                        print("[input-listener] 'cancel' sent to most recent run.")
                    else:
                        print("[input-listener] no active runs to cancel.")
            else:
                print("[input-listener] unknown command (type 'cancel').")

    t = threading.Thread(target=_listener, name="global_input_listener", daemon=True)
    t.start()


# ---------------------- Rate limiting helper ----------------------
def rate_limited_request(account_name: str, func, *args, **kwargs):
    """
    Simple per-account 1 request/sec rate limiter.
    Uses global _last_request_time map which is reset per-run by trade_tcl.
    """
    with _state_lock:
        now = time.time()
        last = _last_request_time.get(account_name)
        if last is not None:
            elapsed = now - last
            if elapsed < 1:
                # sleep outside lock in small increments
                sleep_for = 1 - elapsed
                _state_lock.release()
                try:
                    time.sleep(sleep_for)
                finally:
                    _state_lock.acquire()
        _last_request_time[account_name] = time.time()
    return func(*args, **kwargs)


# ---------------------- Signature / manual POST helper ----------------------
def _make_signature(api_key: str, api_secret: str, recv_window: str, timestamp_ms: str, body_json: str) -> str:
    payload = f"{timestamp_ms}{api_key}{recv_window}{body_json}"
    return hmac.new(api_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def signed_post(base_url: str, api_key: str, api_secret: str, path: str, body: dict, recv_window_ms: int = RECV_WINDOW_MS, timeout: int = 10) -> dict:
    timestamp = str(int(time.time() * 1000))
    body_json = json.dumps(body, separators=(",", ":"))
    sign = _make_signature(api_key, api_secret, str(recv_window_ms), timestamp, body_json)

    headers = {
        "X-BAPI-API-KEY": api_key,
        "X-BAPI-SIGN": sign,
        "X-BAPI-SIGN-TYPE": "2",
        "X-BAPI-TIMESTAMP": timestamp,
        "X-BAPI-RECV-WINDOW": str(recv_window_ms),
        "Content-Type": "application/json",
    }

    url = base_url.rstrip("/") + path
    resp = requests.post(url, headers=headers, data=body_json, timeout=timeout)
    try:
        return resp.json()
    except ValueError:
        return {"http_status": resp.status_code, "text": resp.text}


def make_account_actions(api_key: str, api_secret: str, demo: bool = True, recv_window_ms: int = RECV_WINDOW_MS):
    base = "https://api-demo.bybit.com" if demo else "https://api.bybit.com"

    def place_order(body):
        return signed_post(base, api_key, api_secret, "/v5/order/create", body, recv_window_ms)

    def cancel_order(body):
        return signed_post(base, api_key, api_secret, "/v5/order/cancel", body, recv_window_ms)

    def set_trading_stop(body):
        return signed_post(base, api_key, api_secret, "/v5/position/trading-stop", body, recv_window_ms)

    def set_leverage(body):
        return signed_post(base, api_key, api_secret, "/v5/position/set-leverage", body, recv_window_ms)

    return {
        "place_order": place_order,
        "cancel_order": cancel_order,
        "set_trading_stop": set_trading_stop,
        "set_leverage": set_leverage,
        "base_url": base,
    }


# ---------------------- Helpers ----------------------
def reset_runtime_state():
    """Clear global runtime maps and encourage GC."""
    with _state_lock:
        _last_request_time.clear()
    try:
        gc.collect()
    except Exception:
        pass
    print("[DEBUG] reset_runtime_state(): cleared global runtime maps and ran GC.")


def fetch_open_orders_safe(session, symbol: str):
    candidates = [
        "get_open_orders",
        "query_active_order",
        "get_active_order",
        "query_order",
        "get_order_list",
        "get_open_order",
        "get_orders",
        "get_order_history",
    ]
    last_exc = None
    for name in candidates:
        fn = getattr(session, name, None)
        if not callable(fn):
            continue
        try:
            resp = fn(category="linear", symbol=symbol)
            if isinstance(resp, dict):
                result = resp.get("result")
                if isinstance(result, dict):
                    if "list" in result and isinstance(result["list"], list):
                        return result["list"]
                    if "data" in result and isinstance(result["data"], list):
                        return result["data"]
                if isinstance(result, list):
                    return result
                if "data" in resp and isinstance(resp["data"], list):
                    return resp["data"]
            if isinstance(resp, list):
                return resp
        except Exception as e:
            last_exc = e
            continue
    if last_exc:
        raise last_exc
    raise AttributeError("No supported open-order fetch method found on session")


# ---------------------- Main run (re-entrant) ----------------------
def trade_tcl(keys_dict: Dict[str, Dict[str, str]],
              order_dict: Dict[str, Any],
              tpsl_dict: Dict[str, Any],
              demo: bool = True,
              max_wait_seconds: int = 300) -> Dict[str, Any]:
    """
    keys_dict: {"acc1":{"api_key":"...","api_secret":"..."}, ...}
    order_dict: {"coin":"BTCUSDT","side":"Buy","leverage":..,"qty1":..,"limit1":..,...}
    tpsl_dict: {"symbol":"BTCUSDT","tp1":..,"sl1":..,...}
    demo: use demo endpoints
    """
    # ensure single global input listener exists
    _start_global_input_listener_once()

    # reset per-run global state
    reset_runtime_state()

    # informational time drift check
    try:
        ntp_ts = _fetch_ntp_time_ms()
        local_ts = int(time.time() * 1000)
        if ntp_ts is not None:
            drift = local_ts - ntp_ts
            print(f"[INFO] Local ms: {local_ts} | NTP ms: {ntp_ts} | drift (local - server) = {drift} ms")
            if abs(drift) > RECV_WINDOW_MS:
                print(f"[WARN] Absolute drift ({abs(drift)} ms) exceeds recv_window ({RECV_WINDOW_MS} ms).")
        else:
            bybit_ts = _fetch_bybit_server_time_ms(demo=demo)
            if bybit_ts is not None:
                drift = local_ts - bybit_ts
                print(f"[INFO] Local ms: {local_ts} | Bybit ms: {bybit_ts} | drift (local - server) = {drift} ms (NTP unavailable)")
            else:
                print("[INFO] Could not determine authoritative server time before start.")
    except Exception:
        print("[INFO] Time check failed (exception). Continuing.")

    # per-run containers
    results: Dict[str, list] = {}
    sessions: Dict[str, Any] = {}
    actions: Dict[str, Dict[str, Any]] = {}
    final_summary: Dict[str, Any] = {acc: {"filled": [], "canceled": [], "timeout": False, "done": False, "user_cancel": False}
                                     for acc in keys_dict.keys()}
    order_timestamps: Dict[str, float] = {}
    stop_event = threading.Event()            # signals full-run stop
    cancel_requested: Dict[str, bool] = {"flag": False}  # per-run cancel (set by input listener)
    # map orderLinkId -> limit index for orders placed by this run
    orderlinkid_to_limit: Dict[str, Dict[str, int]] = {acc: {} for acc in keys_dict.keys()}
    pending_orderlinks: Dict[str, Set[str]] = {acc: set() for acc in keys_dict.keys()}
    processed_fills: Dict[str, Set[str]] = {acc: set() for acc in keys_dict.keys()}
    active_position_flag: Dict[str, bool] = {acc: False for acc in keys_dict.keys()}
    lock = threading.RLock()
    fill_events = queue.Queue()

    # create a run-local cancel event and register it to global listener (most-recent semantics)
    run_cancel_event = threading.Event()
    with _global_input_listener_lock:
        _global_active_run_events.append(run_cancel_event)

    # We'll set price/time patch for the duration of the run
    with use_ntp_time_patch(verbose=True, ntp_servers=NTP_SERVERS, demo_fallback=True):
        # ---------- Per-account placement ----------
        def place_orders(account_name: str, creds: Dict[str, str]):
            try:
                session = HTTP(api_key=creds["api_key"], api_secret=creds["api_secret"], demo=demo, recv_window=RECV_WINDOW_MS)
            except TypeError:
                session = HTTP(api_key=creds["api_key"], api_secret=creds["api_secret"], testnet=demo, recv_window=RECV_WINDOW_MS)
            sessions[account_name] = session
            actions[account_name] = make_account_actions(creds["api_key"], creds["api_secret"], demo=demo, recv_window_ms=RECV_WINDOW_MS)

            # set leverage (manual POST)
            try:
                lev_body = {"category": "linear", "symbol": order_dict["coin"], "buyLeverage": str(order_dict["leverage"]), "sellLeverage": str(order_dict["leverage"])}
                rate_limited_request(account_name, actions[account_name]["set_leverage"], lev_body)
            except Exception as e:
                print(f"[{account_name}] ⚠️ Error setting leverage (manual): {e}")

            results[account_name] = []
            order_timestamps[account_name] = time.time()

            for i in range(1, 4):
                order_link_id = f"{account_name}_limit{i}_{uuid.uuid4().hex[:8]}"
                body = {
                    "category": "linear",
                    "symbol": order_dict["coin"],
                    "side": order_dict["side"],
                    "orderType": "Limit",
                    "qty": str(order_dict[f"qty{i}"]),
                    "price": str(order_dict[f"limit{i}"]),
                    "timeInForce": "GTC",
                    "orderLinkId": order_link_id
                }
                try:
                    resp = rate_limited_request(account_name, actions[account_name]["place_order"], body)
                    if isinstance(resp, dict) and resp.get("retCode") == 0:
                        with lock:
                            results[account_name].append({"orderLinkId": order_link_id})
                            orderlinkid_to_limit[account_name][order_link_id] = i
                            pending_orderlinks[account_name].add(order_link_id)
                        print(f"[{account_name}] 📌 Limit{i} placed (orderLinkId={order_link_id}) @ {order_dict[f'limit{i}']}")
                    else:
                        print(f"[{account_name}] ⚠️ Error placing Limit{i} (manual): {resp}")
                except Exception as e:
                    print(f"[{account_name}] ⚠️ Exception placing Limit{i}: {e}")
                # ensure ~1 req/sec
                time.sleep(1)

        # create and join placement threads
        place_threads = []
        for acc, creds in keys_dict.items():
            t = threading.Thread(target=place_orders, args=(acc, creds), name=f"place_{acc}", daemon=False)
            place_threads.append(t)
            t.start()
        for t in place_threads:
            t.join()

        print("[DEBUG] ✅ All accounts placed orders.")

        # ---------- TPSL worker ----------
        def tpsl_worker():
            while not stop_event.is_set():
                # allow external cancel via global input listener
                if run_cancel_event.is_set():
                    with lock:
                        cancel_requested["flag"] = True
                    stop_event.set()
                    break
                try:
                    acc, order_link_id = fill_events.get(timeout=1)
                except queue.Empty:
                    continue

                if stop_event.is_set():
                    break

                with lock:
                    if order_link_id in processed_fills[acc]:
                        continue
                    processed_fills[acc].add(order_link_id)

                limit_num = orderlinkid_to_limit.get(acc, {}).get(order_link_id)
                if limit_num is None:
                    print(f"[{acc}] ⚠️ Unknown orderLinkId {order_link_id} in TPSL worker")
                    continue

                tp = tpsl_dict.get(f"tp{limit_num}")
                sl = tpsl_dict.get(f"sl{limit_num}")
                if tp is None or sl is None:
                    print(f"[{acc}] ⚠️ Missing TP/SL for limit {limit_num}")
                    continue

                try:
                    body = {"category": "linear", "symbol": tpsl_dict["symbol"], "takeProfit": str(tp), "stopLoss": str(sl), "positionIdx": 0}
                    resp = rate_limited_request(acc, actions[acc]["set_trading_stop"], body)
                    code = resp.get("retCode") if isinstance(resp, dict) else None
                    if code in (0, 34040):
                        with lock:
                            final_summary[acc]["filled"].append(f"Limit{limit_num}")
                            active_position_flag[acc] = True
                        print(f"[{acc}] ✅ Limit{limit_num} filled → TP/SL set (tp={tp} sl={sl}) (code={code}).")
                        # start position monitor for this account
                        t = threading.Thread(target=position_monitor, args=(acc,), name=f"posmon_{acc}", daemon=False)
                        t.start()
                    else:
                        print(f"[{acc}] ⚠️ set_trading_stop failed: {resp}")
                except Exception as e:
                    print(f"[{acc}] ⚠️ Error setting TP/SL for Limit{limit_num}: {e}")

        # ---------- Polling worker ----------
        def polling_worker():
            processed_local = {acc: set() for acc in keys_dict.keys()}
            while not stop_event.is_set():
                # allow external cancel
                if run_cancel_event.is_set():
                    with lock:
                        cancel_requested["flag"] = True
                    stop_event.set()
                    break

                for acc in list(keys_dict.keys()):
                    if stop_event.is_set():
                        break
                    session = sessions.get(acc)
                    if session is None:
                        continue
                    if not pending_orderlinks[acc]:
                        continue

                    try:
                        try:
                            orders = fetch_open_orders_safe(session, tpsl_dict["symbol"])
                        except Exception:
                            orders = []

                        found_links = set()
                        for order in orders:
                            order_link = order.get("orderLinkId")
                            status = order.get("orderStatus") or order.get("status") or order.get("order_status")
                            if not order_link:
                                continue
                            found_links.add(order_link)
                            if order_link not in orderlinkid_to_limit.get(acc, {}):
                                continue
                            if str(status).lower() in ("filled", "complete", "closed"):
                                if order_link not in processed_local[acc]:
                                    processed_local[acc].add(order_link)
                                    with lock:
                                        pending_orderlinks[acc].discard(order_link)
                                    fill_events.put((acc, order_link))
                                    print(f"[DEBUG] [{acc}] Order {order_link} detected as filled (status={status}).")

                        # fallback: missing from open-orders -> check history
                        missing = set(pending_orderlinks[acc]) - found_links
                        if missing:
                            for missing_link in list(missing):
                                if stop_event.is_set():
                                    break
                                try:
                                    history_fn = getattr(session, "get_order_history", None) or getattr(session, "query_order", None) or getattr(session, "query_active_order", None) or getattr(session, "get_orders", None)
                                    if callable(history_fn):
                                        resp = rate_limited_request(acc, history_fn, category="linear", symbol=tpsl_dict["symbol"], orderLinkId=missing_link, limit=20)
                                        hist = []
                                        if isinstance(resp, dict):
                                            res = resp.get("result")
                                            if isinstance(res, dict):
                                                hist = res.get("list") or res.get("data") or []
                                            elif isinstance(res, list):
                                                hist = res
                                        for rec in hist:
                                            status = rec.get("orderStatus") or rec.get("status")
                                            if str(status).lower() in ("filled", "complete", "closed"):
                                                with lock:
                                                    pending_orderlinks[acc].discard(missing_link)
                                                fill_events.put((acc, missing_link))
                                                print(f"[DEBUG] [{acc}] (history) Order {missing_link} detected as filled (status={status}).")
                                                break
                                except Exception as e:
                                    print(f"[{acc}] ⚠️ Error checking history for {missing_link}: {e}")
                    except Exception as e:
                        print(f"[{acc}] ⚠️ Error polling orders: {e}")

                # responsive sleep
                for _ in range(10):
                    if stop_event.is_set() or run_cancel_event.is_set():
                        break
                    time.sleep(0.1)

        # ---------- Position monitor ----------
        def position_monitor(account_name: str):
            waited_for_position = False
            while not stop_event.is_set():
                if run_cancel_event.is_set():
                    with lock:
                        cancel_requested["flag"] = True
                    stop_event.set()
                    break

                if not active_position_flag.get(account_name):
                    time.sleep(0.5)
                    continue
                try:
                    pos_resp = rate_limited_request(account_name, sessions[account_name].get_positions, category="linear", symbol=tpsl_dict["symbol"])
                    positions = pos_resp.get("result", {}).get("list", []) if isinstance(pos_resp, dict) else []
                    size = 0.0
                    if positions:
                        try:
                            size = float(positions[0].get("size", 0))
                        except Exception:
                            size = 0.0
                    if not waited_for_position:
                        if size > 0:
                            waited_for_position = True
                            print(f"[{account_name}] 🔎 Position detected (size={size}). Now monitoring for close (TP/SL).")
                    else:
                        if size == 0:
                            print(f"[{account_name}] ✅ Position closed (TP/SL hit or manual close). Cancelling remaining limit orders...")
                            try:
                                with lock:
                                    to_cancel = list(pending_orderlinks[account_name])
                                for link in to_cancel:
                                    try:
                                        cancel_body = {"category": "linear", "symbol": tpsl_dict["symbol"], "orderLinkId": link}
                                        resp = rate_limited_request(account_name, actions[account_name]["cancel_order"], cancel_body)
                                        with lock:
                                            final_summary[account_name]["canceled"].append(link)
                                            pending_orderlinks[account_name].discard(link)
                                        print(f"[{account_name}] ❌ Cancelled leftover order {link} after position closed. resp={resp}")
                                    except Exception as e:
                                        print(f"[{account_name}] ⚠️ Error cancelling {link}: {e}")
                            except Exception as e:
                                print(f"[{account_name}] ⚠️ Error during cancel-after-close: {e}")
                            with lock:
                                active_position_flag[account_name] = False
                            return
                except Exception as e:
                    print(f"[{account_name}] ⚠️ Error fetching positions: {e}")
                for _ in range(5):
                    if stop_event.is_set() or run_cancel_event.is_set():
                        break
                    time.sleep(0.2)

        # ---------- Start background threads ----------
        worker_threads = []
        t_poll = threading.Thread(target=polling_worker, name="polling_worker", daemon=False)
        t_poll.start()
        worker_threads.append(t_poll)
        t_tpsl = threading.Thread(target=tpsl_worker, name="tpsl_worker", daemon=False)
        t_tpsl.start()
        worker_threads.append(t_tpsl)

        # ---------- Main controller loop ----------
        try:
            while True:
                # if global input asked to cancel this run, mark cancel_requested
                if run_cancel_event.is_set():
                    with lock:
                        cancel_requested["flag"] = True
                    stop_event.set()
                    break

                all_done = True
                now = time.time()

                for acc in list(keys_dict.keys()):
                    if final_summary[acc]["done"]:
                        continue

                    if cancel_requested["flag"]:
                        # immediate cancel+close for this run only
                        print(f"[{acc}] ⛔ User requested cancel. Cancelling outstanding orders and closing positions (this run).")
                        try:
                            with lock:
                                to_cancel = list(pending_orderlinks[acc])
                            for olnk in to_cancel:
                                try:
                                    cancel_body = {"category": "linear", "symbol": tpsl_dict["symbol"], "orderLinkId": olnk}
                                    resp = rate_limited_request(acc, actions[acc]["cancel_order"], cancel_body)
                                    with lock:
                                        final_summary[acc]["canceled"].append(olnk)
                                        pending_orderlinks[acc].discard(olnk)
                                    print(f"[{acc}] ❌ Cancel resp: {resp}")
                                except Exception as e:
                                    print(f"[{acc}] ⚠️ Error cancelling {olnk}: {e}")

                            # close only positions that this run created (active_position_flag)
                            if active_position_flag.get(acc):
                                pos_info = rate_limited_request(acc, sessions[acc].get_positions, category="linear", symbol=tpsl_dict["symbol"])
                                for p in pos_info.get("result", {}).get("list", []):
                                    size = float(p.get("size", 0))
                                    side = p.get("side")
                                    if size > 0:
                                        close_side = "Sell" if side == "Buy" else "Buy"
                                        close_body = {
                                            "category": "linear",
                                            "symbol": tpsl_dict["symbol"],
                                            "side": close_side,
                                            "orderType": "Market",
                                            "qty": str(size),
                                            "reduceOnly": True,
                                            "timeInForce": "GTC",
                                            "orderLinkId": f"cancel_close_{acc}_{int(time.time() * 1000)}"
                                        }
                                        resp = rate_limited_request(acc, actions[acc]["place_order"], close_body)
                                        print(f"[{acc}] 🛑 Close resp: {resp}")
                                with lock:
                                    active_position_flag[acc] = False
                        except Exception as e:
                            print(f"[{acc}] ⚠️ Error during cancel sequence: {e}")

                        final_summary[acc]["user_cancel"] = True
                        final_summary[acc]["done"] = True
                        stop_event.set()
                        continue

                    # timeout handling (selective)
                    if order_timestamps.get(acc) and now - order_timestamps[acc] > max_wait_seconds:
                        print(f"[{acc}] ⏳ Timeout reached — cancelling remaining orders placed by this run and closing this run's position (if any).")
                        try:
                            # cancel only pending orders this run placed
                            with lock:
                                to_cancel = list(pending_orderlinks[acc])
                            for olnk in to_cancel:
                                try:
                                    cancel_body = {"category": "linear", "symbol": tpsl_dict["symbol"], "orderLinkId": olnk}
                                    resp = rate_limited_request(acc, actions[acc]["cancel_order"], cancel_body)
                                    with lock:
                                        final_summary[acc]["canceled"].append(olnk)
                                        pending_orderlinks[acc].discard(olnk)
                                    print(f"[{acc}] ❌ Cancelled (timeout) order {olnk}. resp={resp}")
                                except Exception as e:
                                    print(f"[{acc}] ⚠️ Error cancelling {olnk}: {e}")

                            # close only position opened by this run
                            if active_position_flag.get(acc):
                                pos_info = rate_limited_request(acc, sessions[acc].get_positions, category="linear", symbol=tpsl_dict["symbol"])
                                for p in pos_info.get("result", {}).get("list", []):
                                    try:
                                        size = float(p.get("size", 0))
                                        side = p.get("side")
                                        if size > 0:
                                            close_side = "Sell" if side == "Buy" else "Buy"
                                            close_body = {
                                                "category": "linear",
                                                "symbol": tpsl_dict["symbol"],
                                                "side": close_side,
                                                "orderType": "Market",
                                                "qty": str(size),
                                                "reduceOnly": True,
                                                "timeInForce": "GTC",
                                                "orderLinkId": f"timeout_close_{acc}_{int(time.time() * 1000)}"
                                            }
                                            resp = rate_limited_request(acc, actions[acc]["place_order"], close_body)
                                            print(f"[{acc}] 🛑 Timeout close resp: {resp}")
                                    except Exception as e:
                                        print(f"[{acc}] ⚠️ Error closing position on timeout: {e}")
                                with lock:
                                    active_position_flag[acc] = False
                        except Exception as e:
                            print(f"[{acc}] ⚠️ Error during timeout cleanup: {e}")
                        final_summary[acc]["timeout"] = True
                        final_summary[acc]["done"] = True
                        continue

                    # still waiting for fills or active position
                    if pending_orderlinks[acc] or active_position_flag[acc]:
                        all_done = False
                    else:
                        final_summary[acc]["done"] = True

                if all_done:
                    stop_event.set()
                    break

                # small responsive sleep
                for _ in range(10):
                    if stop_event.is_set() or run_cancel_event.is_set():
                        break
                    time.sleep(0.1)

        except KeyboardInterrupt:
            print("[DEBUG] KeyboardInterrupt received, stopping.")
            stop_event.set()
        except Exception as e:
            print("[DEBUG] Unexpected exception in controller loop:", e)
            traceback.print_exc()
            stop_event.set()

        # ------- Clean up threads and sessions -------
        # signal stop to workers (already set)
        stop_event.set()

        # join worker threads
        for t in worker_threads:
            try:
                if t.is_alive():
                    t.join(timeout=2)
            except Exception:
                pass

        # Also join any posmon_*/place_* threads (best effort)
        for t in threading.enumerate():
            if t.name.startswith(("posmon_", "place_")) and t is not threading.current_thread():
                try:
                    t.join(timeout=1)
                except Exception:
                    pass

        # Close pybit underlying sessions if possible
        for acc, s in list(sessions.items()):
            try:
                sess_obj = getattr(s, "session", None) or getattr(s, "http", None)
                if hasattr(sess_obj, "close"):
                    sess_obj.close()
            except Exception:
                pass

        # final GC
        try:
            gc.collect()
        except Exception:
            pass

    # unregister run_cancel_event from global list
    with _global_input_listener_lock:
        try:
            _global_active_run_events.remove(run_cancel_event)
        except ValueError:
            pass

    print("[DEBUG] Exiting trade_tcl, summary:")
    print(json.dumps(final_summary, indent=2))
    return final_summary
