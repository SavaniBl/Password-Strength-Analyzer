#!/usr/bin/env python3
"""
Password Strength Analyzer
Checks password strength via entropy, pattern detection, and HaveIBeenPwned API.
"""

import re
import math
import hashlib
import urllib.request
import urllib.error
import argparse
import sys
import getpass
from dataclasses import dataclass, field
from typing import Optional

# ── ANSI colors ────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"

# ── Scoring weights ─────────────────────────────────────────────────────────────
SCORE_WEIGHTS = {
    "length_ok":        10,
    "length_great":     10,
    "uppercase":        10,
    "lowercase":        10,
    "digits":           10,
    "special":          15,
    "high_entropy":     15,
    "no_common_word":   10,
    "no_keyboard_walk": 5,
    "no_repeats":       5,
}
MAX_SCORE = sum(SCORE_WEIGHTS.values())

COMMON_WORDS = {
    "password", "passw0rd", "password1", "qwerty", "letmein", "welcome",
    "monkey", "dragon", "master", "admin", "login", "superman", "batman",
    "iloveyou", "sunshine", "princess", "shadow", "football", "baseball",
    "abc123", "123456", "111111", "696969", "trustno1", "starwars",
}

KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1234567890", "0987654321", "abcdef", "abcdefgh",
]

# ── Data classes ────────────────────────────────────────────────────────────────
@dataclass
class AnalysisResult:
    password:         str
    length:           int
    entropy:          float
    charset_size:     int
    score:            int
    label:            str
    color:            str
    checks:           dict = field(default_factory=dict)
    suggestions:      list = field(default_factory=list)
    pwned_count:      Optional[int] = None
    pwned_error:      Optional[str] = None

# ── Core analysis ───────────────────────────────────────────────────────────────
def compute_charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password): size += 26
    if re.search(r"[A-Z]", password): size += 26
    if re.search(r"\d",    password): size += 10
    if re.search(r"[^a-zA-Z0-9]", password): size += 32
    return size or 1

def compute_entropy(password: str) -> float:
    charset = compute_charset_size(password)
    return len(password) * math.log2(charset)

def detect_repeats(password: str) -> bool:
    """Return True if password has 3+ consecutive repeated characters."""
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return True
    return False

def detect_keyboard_walk(password: str) -> bool:
    lower = password.lower()
    for walk in KEYBOARD_WALKS:
        for length in range(4, len(walk) + 1):
            for start in range(len(walk) - length + 1):
                chunk = walk[start:start + length]
                if chunk in lower or chunk[::-1] in lower:
                    return True
    return False

def analyze(password: str) -> AnalysisResult:
    length = len(password)
    entropy = compute_entropy(password)
    charset = compute_charset_size(password)
    lower = password.lower()

    has_upper   = bool(re.search(r"[A-Z]", password))
    has_lower   = bool(re.search(r"[a-z]", password))
    has_digit   = bool(re.search(r"\d",   password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))
    high_entropy  = entropy >= 60
    no_common     = lower not in COMMON_WORDS and not any(w in lower for w in COMMON_WORDS)
    no_walk       = not detect_keyboard_walk(password)
    no_repeats    = not detect_repeats(password)
    length_ok     = length >= 8
    length_great  = length >= 14

    checks = {
        "length_ok":        length_ok,
        "length_great":     length_great,
        "uppercase":        has_upper,
        "lowercase":        has_lower,
        "digits":           has_digit,
        "special":          has_special,
        "high_entropy":     high_entropy,
        "no_common_word":   no_common,
        "no_keyboard_walk": no_walk,
        "no_repeats":       no_repeats,
    }

    score = sum(SCORE_WEIGHTS[k] for k, v in checks.items() if v)

    suggestions = []
    if not length_ok:        suggestions.append("Use at least 8 characters")
    if not length_great:     suggestions.append("Aim for 14+ characters for better security")
    if not has_upper:        suggestions.append("Add uppercase letters (A-Z)")
    if not has_lower:        suggestions.append("Add lowercase letters (a-z)")
    if not has_digit:        suggestions.append("Add numbers (0-9)")
    if not has_special:      suggestions.append("Add special characters (!@#$%^&*...)")
    if not no_common:        suggestions.append("Avoid common words or patterns")
    if not no_walk:          suggestions.append("Avoid keyboard walks (e.g. qwerty, asdf)")
    if not no_repeats:       suggestions.append("Avoid 3+ repeated characters (e.g. aaa)")
    if not high_entropy:     suggestions.append(f"Current entropy {entropy:.1f} bits — aim for 60+")

    pct = score / MAX_SCORE
    if pct >= 0.85:   label, color = "Strong",    GREEN
    elif pct >= 0.65: label, color = "Good",      CYAN
    elif pct >= 0.45: label, color = "Fair",      YELLOW
    else:             label, color = "Weak",      RED

    return AnalysisResult(
        password=password,
        length=length,
        entropy=entropy,
        charset_size=charset,
        score=score,
        label=label,
        color=color,
        checks=checks,
        suggestions=suggestions,
    )

# ── HaveIBeenPwned ──────────────────────────────────────────────────────────────
def check_hibp(password: str) -> tuple[Optional[int], Optional[str]]:
    """
    k-Anonymity model: only first 5 chars of SHA-1 hash are sent.
    Returns (count, error_message).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "PasswordAnalyzerCLI/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")

        for line in body.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count), None
        return 0, None

    except urllib.error.URLError as e:
        return None, f"Network error: {e.reason}"
    except Exception as e:
        return None, str(e)

# ── Display ─────────────────────────────────────────────────────────────────────
def bar(score: int, max_score: int, width: int = 30) -> str:
    filled = round(score / max_score * width)
    pct = score / max_score
    if pct >= 0.85:   clr = GREEN
    elif pct >= 0.65: clr = CYAN
    elif pct >= 0.45: clr = YELLOW
    else:             clr = RED
    return f"{clr}{'█' * filled}{'░' * (width - filled)}{RESET}"

def check_icon(passed: bool) -> str:
    return f"{GREEN}✔{RESET}" if passed else f"{RED}✘{RESET}"

LABELS = {
    "length_ok":        "At least 8 characters",
    "length_great":     "At least 14 characters",
    "uppercase":        "Contains uppercase (A-Z)",
    "lowercase":        "Contains lowercase (a-z)",
    "digits":           "Contains digits (0-9)",
    "special":          "Contains special characters",
    "high_entropy":     "High entropy (≥60 bits)",
    "no_common_word":   "No common password patterns",
    "no_keyboard_walk": "No keyboard walk (qwerty…)",
    "no_repeats":       "No 3+ repeated chars (aaa…)",
}

def print_report(r: AnalysisResult, show_password: bool = False) -> None:
    print()
    print(f"  {BOLD}{'─' * 50}{RESET}")
    print(f"  {BOLD}  Password Strength Analyzer{RESET}")
    print(f"  {'─' * 50}")
    print()

    if show_password:
        masked = r.password
    else:
        masked = r.password[:2] + "•" * (r.length - 4) + r.password[-2:] if r.length > 4 else "•" * r.length
    print(f"  {GRAY}Password :{RESET} {WHITE}{masked}{RESET}")
    print(f"  {GRAY}Length   :{RESET} {r.length} characters")
    print(f"  {GRAY}Charset  :{RESET} {r.charset_size} possible characters")
    print(f"  {GRAY}Entropy  :{RESET} {r.entropy:.1f} bits")
    print()

    print(f"  {BOLD}Strength{RESET}")
    score_pct = round(r.score / MAX_SCORE * 100)
    print(f"  {bar(r.score, MAX_SCORE)}  {r.color}{BOLD}{r.label}{RESET}  ({score_pct}%)")
    print()

    print(f"  {BOLD}Security Checks{RESET}")
    for key, passed in r.checks.items():
        weight = SCORE_WEIGHTS[key]
        pts = f"{GRAY}+{weight}pts{RESET}" if passed else f"{GRAY}    {RESET}"
        print(f"  {check_icon(passed)}  {LABELS[key]:<38} {pts}")
    print()

    # HIBP result
    if r.pwned_count is not None:
        if r.pwned_count == 0:
            print(f"  {GREEN}✔{RESET}  {BOLD}Not found{RESET} in HaveIBeenPwned database  {GRAY}(k-Anonymity API){RESET}")
        else:
            print(f"  {RED}✘{RESET}  {BOLD}LEAKED!{RESET} Found {RED}{r.pwned_count:,}{RESET} times in data breaches  {GRAY}(HaveIBeenPwned){RESET}")
    elif r.pwned_error:
        print(f"  {YELLOW}⚠{RESET}  HaveIBeenPwned check skipped: {GRAY}{r.pwned_error}{RESET}")
    print()

    if r.suggestions:
        print(f"  {BOLD}Suggestions{RESET}")
        for s in r.suggestions:
            print(f"  {YELLOW}→{RESET}  {s}")
        print()

    print(f"  {'─' * 50}")
    print()

# ── CLI entry point ─────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="password-analyzer",
        description="Analyze password strength, entropy, and breach exposure.",
    )
    parser.add_argument(
        "password", nargs="?",
        help="Password to analyze (omit for secure prompt)",
    )
    parser.add_argument(
        "--no-hibp", action="store_true",
        help="Skip HaveIBeenPwned API check",
    )
    parser.add_argument(
        "--show", action="store_true",
        help="Show password in output (masked by default)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON",
    )
    args = parser.parse_args()

    # Get password
    if args.password:
        password = args.password
    else:
        try:
            password = getpass.getpass("  Enter password: ")
        except (KeyboardInterrupt, EOFError):
            print("\n  Aborted.")
            sys.exit(0)

    if not password:
        print("  Error: password cannot be empty.", file=sys.stderr)
        sys.exit(1)

    # Analyze
    result = analyze(password)

    # HIBP check
    if not args.no_hibp:
        count, err = check_hibp(password)
        result.pwned_count = count
        result.pwned_error = err

    # Output
    if args.json:
        import json
        out = {
            "length":       result.length,
            "entropy_bits": round(result.entropy, 2),
            "charset_size": result.charset_size,
            "score":        result.score,
            "max_score":    MAX_SCORE,
            "label":        result.label,
            "checks":       result.checks,
            "suggestions":  result.suggestions,
            "pwned_count":  result.pwned_count,
            "pwned_error":  result.pwned_error,
        }
        print(json.dumps(out, indent=2))
    else:
        print_report(result, show_password=args.show)

    # Exit code: 0 = strong/good, 1 = fair/weak, 2 = leaked
    if result.pwned_count and result.pwned_count > 0:
        sys.exit(2)
    elif result.label in ("Weak", "Fair"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
