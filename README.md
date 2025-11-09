# Interactive Timing Side-Channel Attack

This project demonstrates a **timing-based side-channel attack** on a vulnerable password verification server.
It measures subtle timing differences to infer the correct password, one character at a time.

---

## 🧠 Overview

The attack works in **two phases**:

1. **Phase 1 — Find Password Length:**
   Tries passwords of increasing length (`"a"`, `"aa"`, `"aaa"`, ...) to detect where response time increases.

2. **Phase 2 — Crack Password Character-by-Character:**
   For each position, it tests all possible characters (a–z) and selects the one causing the longest response time.

The script supports **multi-threaded measurement**, **median timing analysis**, and an optional **ranking mode** that improves speed by testing fewer characters in the full round.

---

## ⚙️ Requirements

- Python 3.8 or newer
- `requests` package

Install dependencies:

```bash
pip install requests
```

---

## 🐳 Running the Vulnerable Server (Docker)


## 🚀 Quick Start

1. **Terminal 1: Start the Server**
```powershell
.\docker.bat
```
2. **Terminal 2: Run the attack script:**

```bash
python attack.py
```

3. Follow the on-screen instructions to:
   - Enter username, difficulty, and parameters.
   - Choose between:
     - Phase 1 (find password length)
     - Phase 2 (crack known length)
     - Full attack (both phases)

4. When finished, a summary file is saved under `attack_runs/`.

---

## 📁 Output Files

- **`attack_runs/run_summary_*.txt`** — concise text summary
- **`attack_runs/run_summary_*.json`** — detailed JSON log (includes per-character timings)

---

## 🧩 Project Structure

```
attack.py                 # Main attack script
docker.bat                # Docker server startup (Windows) ⭐
attack_runs/              # Folder for results
.gitignore                # Ignored files (env, logs, etc.)
README.md                 # This file
```

---

## 🧰 Notes

- The ranking system speeds up attacks by doing a quick pre-check (1–3 measurements per char) and then verifying only the best candidates (5–8 measurements).
- Timings are printed with full precision and timestamps at every stage.
- Safe for lab/educational use only.

---

### Our Attack Strategy

#### **Phase 1: Find Password Length**

**Why?** We need to know the length to pad our guesses correctly.

**How?**
1. Try passwords: "a", "aa", "aaa", "aaaa", etc.
2. Measure response time for each length
3. The **correct length** takes slightly LONGER
4. Why? It checks all positions before returning False

**Example:**
```
Length 1 ("a"):     0.010234s  ← Wrong length, quick exit
Length 2 ("aa"):    0.010256s  ← Wrong length, quick exit
Length 3 ("aaa"):   0.010289s  ← Wrong length, quick exit
Length 4 ("aaaa"):  0.010312s  ← Wrong length, quick exit
Length 5 ("aaaaa"): 0.010567s  ← LONGEST! This is the correct length
```

**Result:** Password length = 5

---

#### **Phase 2: Crack Character-by-Character**

**Why padding?** We must send passwords of the correct length for timing differences to work.

**How?**
1. For position 0, try: "a____", "b____", ..., "h____" (pad with 'a')
2. Measure timing for each
3. Correct character takes LONGER (progresses to position 1)
4. Wrong character exits immediately (faster)
5. Pick the character with longest time
6. Repeat for next position

**Example (password = "hello", length = 5):**

```
Position 0:
  "a____": 0.010234s  ← Wrong char, exits at position 0
  "b____": 0.010256s  ← Wrong char, exits at position 0
  "h____": 0.010523s  ← LONGEST! Correct, progresses to position 1
  Result: First char = 'h'

Position 1 (known = "h"):
  "ha___": 0.010523s  ← Wrong char, exits at position 1
  "hb___": 0.010534s  ← Wrong char, exits at position 1
  "he___": 0.010789s  ← LONGEST! Correct, progresses to position 2
  Result: Second char = 'e'

Position 2 (known = "he"):
  "hea__": 0.010789s
  "heb__": 0.010801s
  "hel__": 0.011034s  ← LONGEST!
  Result: Third char = 'l'

Continue... → "hello"
```

---

### ⚡ Optimization: Parallel Execution

**Problem:** Testing 26 letters × 10 measurements = 260 requests per position (slow!)

**Solution:** Use `ThreadPoolExecutor` to send multiple requests simultaneously.

**Benefits:**
- Tests all 26 letters in parallel
- 10 measurements per letter also run in parallel
- **Speed increase: 5-10x faster!**

**Code snippet:**
```python
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(measure_time, ...) for _ in range(measurements)]
    times = [f.result() for f in as_completed(futures)]
```

---

## 📊 Why This Works

### Timing Comparison

| Guess  | Matching Chars | Comparisons Done | Time     |
|--------|----------------|------------------|----------|
| "a____"| 0              | 1                | ~10.00ms |
| "h____"| 1              | 2                | ~10.05ms | ← Slightly longer!
| "he___"| 2              | 3                | ~10.10ms | ← Even longer!

The pattern: **More matching characters = Longer execution time**

### Complexity Analysis

**Brute Force:**
- For 10-char password: `26^10 = 141,167,095,653,376` attempts
- Time: Thousands of years!

**Our Timing Attack:**
- Length detection: `32 lengths × 5 measurements = 160` attempts
- Character cracking: `10 chars × 26 letters × 10 measurements = 2,600` attempts
- **Total: ~2,760 attempts**
- Time: Minutes!

**Speed-up: ~51 billion times faster! 🚀**

---

## ⚠️ Disclaimer

This code is for **educational purposes only**.
Do **not** use it against systems you do not own or have explicit permission to test.

---
