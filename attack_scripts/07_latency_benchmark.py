"""
Benchmark Latenta Mecanisme de Securitate MFA
===============================================
Masoara latenta introdusa de fiecare strat de securitate:

  1. Login fara MFA             - autentificare simpla (baseline)
  2. Login cu MFA (pasul 1)     - primul factor (email + parola)
  3. Verificare TOTP (pasul 2)  - al doilea factor
  4. Verificare JWT per cerere  - overhead per request protejat
  5. Rate limiting              - latenta dupa activarea limitei
  6. Overhead proxy MitM        - comparatie direct vs prin mitmproxy

Rezultat: media, mediana, p95, deviatia standard pentru fiecare etapa.

Rulare (backend pornit, cu sau fara mitmproxy):
    python 07_latency_benchmark.py
"""

import urllib.request
import urllib.error
import json
import time
import base64
import os
import statistics

# Schimba in 8085 daca vrei sa masori si overhead-ul mitmproxy
BACKEND_DIRECT = "http://localhost:5000/api/v1"
BACKEND_PROXY  = "http://localhost:8085/api/v1"

# Cont fara MFA (pentru baseline)
EMAIL_NO_MFA    = "test.jwt@example.com"
PASSWORD_NO_MFA = "Test123!@#"

# Cont cu MFA activ (pentru masurarea pasului 1 + 2)
EMAIL_MFA    = "test@example.com"
PASSWORD_MFA = "Test123!@#"

ITERATIONS = 10   # rulari per test
SEP  = "-" * 60
SEP2 = "=" * 60


# ── Utilitare HTTP ────────────────────────────────────────────────────────────

def post(url, body, token=None, timeout=10):
    payload = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as ex:
        return 0, {"message": str(ex)}

def get(url, token=None, timeout=10):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as ex:
        return 0, {"message": str(ex)}


# ── Statistici ────────────────────────────────────────────────────────────────

def stats(samples_ms):
    if not samples_ms:
        return {}
    s = sorted(samples_ms)
    p95_idx = max(0, int(len(s) * 0.95) - 1)
    return {
        "n":      len(s),
        "mean":   statistics.mean(s),
        "median": statistics.median(s),
        "min":    min(s),
        "max":    max(s),
        "p95":    s[p95_idx],
        "stdev":  statistics.stdev(s) if len(s) > 1 else 0,
    }

def print_stats(label, s):
    if not s:
        print(f"  {label:<40}: fara date")
        return
    print(f"  {label:<40}: medie={s['mean']:.1f}ms  mediana={s['median']:.1f}ms  "
          f"min={s['min']:.1f}ms  max={s['max']:.1f}ms  p95={s['p95']:.1f}ms  "
          f"stdev={s['stdev']:.1f}ms")


# ── Teste individuale ─────────────────────────────────────────────────────────

def bench_login_no_mfa(base, n):
    """Login simplu fara MFA — returneaza JWT direct."""
    times = []
    token = None
    print(f"  Rulare {n} iteratii login fara MFA...", end=" ", flush=True)
    last_status = None
    for _ in range(n):
        t0 = time.perf_counter()
        status, body = post(f"{base}/auth/login",
                            {"email": EMAIL_NO_MFA, "password": PASSWORD_NO_MFA})
        elapsed = (time.perf_counter() - t0) * 1000
        last_status = status
        if status == 200 and body.get("accessToken"):
            times.append(elapsed)
            token = body["accessToken"]
        time.sleep(0.1)
    if len(times) == 0 and last_status:
        hint = " (rate limit - restarteaza backend-ul)" if last_status == 429 else \
               " (credentiale incorecte)" if last_status == 401 else \
               f" (status {last_status})"
        print(f"EROARE{hint}")
    else:
        print(f"OK ({len(times)}/{n} reusite)")
    return times, token


def bench_login_mfa_step1(base, n):
    """Pasul 1 din autentificarea cu MFA — returneaza tempToken."""
    times = []
    temp_token = None
    print(f"  Rulare {n} iteratii login cu MFA (pasul 1)...", end=" ", flush=True)
    last_status = None
    for _ in range(n):
        t0 = time.perf_counter()
        status, body = post(f"{base}/auth/login",
                            {"email": EMAIL_MFA, "password": PASSWORD_MFA})
        elapsed = (time.perf_counter() - t0) * 1000
        last_status = status
        if status == 200 and (body.get("requireMFA") or body.get("tempToken")):
            times.append(elapsed)
            if not temp_token:
                temp_token = body.get("tempToken")
        time.sleep(0.1)
    if len(times) == 0 and last_status:
        hint = " (rate limit - restarteaza backend-ul)" if last_status == 429 else \
               " (credentiale incorecte sau cont fara MFA)" if last_status == 401 else \
               f" (status {last_status})"
        print(f"EROARE{hint}")
    else:
        print(f"OK ({len(times)}/{n} reusite)")
    return times, temp_token


def bench_profile(base, token, n):
    """GET /auth/profile cu JWT valid — masoara overhead-ul verificarii JWT."""
    times = []
    print(f"  Rulare {n} iteratii GET /profile (JWT verify)...", end=" ", flush=True)
    for _ in range(n):
        t0 = time.perf_counter()
        status, _ = get(f"{base}/auth/profile", token)
        elapsed = (time.perf_counter() - t0) * 1000
        if status == 200:
            times.append(elapsed)
        time.sleep(0.05)
    print(f"OK ({len(times)}/{n} reusite)")
    return times


def bench_totp_invalid(base, temp_token, n):
    """
    Masoara latenta endpoint-ului TOTP cu cod invalid.
    Codul e respins (401) dar masuram cat dureaza procesarea server-side.
    ATENTIE: limitat la 5 incercari din cauza rate limiting-ului.
    """
    times = []
    actual_n = min(n, 4)  # sub limita de rate limiting
    print(f"  Rulare {actual_n} iteratii TOTP verify (cod invalid, sub rate limit)...",
          end=" ", flush=True)
    if not temp_token:
        print("SARIT (nu exista tempToken)")
        return times
    for i in range(actual_n):
        fake_code = f"{(100000 + i * 7):06d}"
        t0 = time.perf_counter()
        status, _ = post(f"{base}/auth/mfa/totp/verify",
                         {"token": fake_code, "method": "totp"},
                         temp_token)
        elapsed = (time.perf_counter() - t0) * 1000
        times.append(elapsed)
        time.sleep(0.2)
    print(f"OK ({len(times)}/{actual_n})")
    return times


def bench_fido2_server_side(base, access_token, n):
    """
    Masoara latenta server-side a verificarii FIDO2 cu un credential fals.
    Serverul primeste raspunsul, incearca sa gaseasca credentialul in DB,
    esueaza (400/401) — dar latenta reflecta procesarea criptografica.
    """
    times = []
    actual_n = min(n, 5)
    print(f"  Rulare {actual_n} iteratii FIDO2 verify (credential fals)...",
          end=" ", flush=True)
    if not access_token:
        print("SARIT (nu exista access token)")
        return times

    def b64url(data):
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    for _ in range(actual_n):
        fake_cred = {
            "id": b64url(os.urandom(32)),
            "rawId": b64url(os.urandom(32)),
            "type": "public-key",
            "response": {
                "clientDataJSON":    b64url(json.dumps({"type":"webauthn.get","challenge":b64url(os.urandom(32)),"origin":"http://localhost:3000"}, separators=(",",":")))  ,
                "authenticatorData": b64url(os.urandom(37)),
                "signature":         b64url(os.urandom(64)),
                "userHandle":        b64url(b"fakeuser"),
            }
        }
        t0 = time.perf_counter()
        status, _ = post(f"{base}/mfa/fido2/complete",
                         {"credential": fake_cred}, access_token)
        elapsed = (time.perf_counter() - t0) * 1000
        times.append(elapsed)
        time.sleep(0.2)

    print(f"OK ({len(times)}/{actual_n}) — raspunsuri 400/401 asteptate")
    return times


def bench_direct_vs_proxy(n):
    """Compara latenta direct la backend vs prin mitmproxy."""
    times_direct = []
    times_proxy  = []

    print(f"  Direct la backend (port 5000)...", end=" ", flush=True)
    for _ in range(n):
        t0 = time.perf_counter()
        status, body = post(f"{BACKEND_DIRECT}/auth/login",
                            {"email": EMAIL_NO_MFA, "password": PASSWORD_NO_MFA})
        elapsed = (time.perf_counter() - t0) * 1000
        if status == 200 and body.get("accessToken"):
            times_direct.append(elapsed)
        time.sleep(0.1)
    print(f"OK ({len(times_direct)}/{n})")

    # Verificam daca mitmproxy e pornit
    print(f"  Prin mitmproxy (port 8085)...", end=" ", flush=True)
    for _ in range(n):
        t0 = time.perf_counter()
        status, body = post(f"{BACKEND_PROXY}/auth/login",
                            {"email": EMAIL_NO_MFA, "password": PASSWORD_NO_MFA})
        elapsed = (time.perf_counter() - t0) * 1000
        if status == 200 and body.get("accessToken"):
            times_proxy.append(elapsed)
        elif status == 0:
            break
        time.sleep(0.1)

    if times_proxy:
        print(f"OK ({len(times_proxy)}/{n})")
    else:
        print(f"SARIT (mitmproxy nu ruleaza pe 8085)")

    return times_direct, times_proxy


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{SEP2}")
    print("  BENCHMARK LATENTA MECANISME DE SECURITATE MFA")
    print(SEP2)
    print(f"  Backend  : {BACKEND_DIRECT}")
    print(f"  Iteratii : {ITERATIONS} per test")
    print(f"{SEP2}\n")

    results = {}

    # ── 1. Login fara MFA ────────────────────────────────────────────────────
    print(f"{SEP}")
    print(f"  [1] LOGIN FARA MFA (baseline)")
    print(SEP)
    t_no_mfa, access_token = bench_login_no_mfa(BACKEND_DIRECT, ITERATIONS)
    results["login_no_mfa"] = stats(t_no_mfa)

    # ── 2. Login cu MFA pasul 1 ──────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  [2] LOGIN CU MFA — PASUL 1 (email + parola -> tempToken)")
    print(SEP)
    t_mfa_s1, temp_token = bench_login_mfa_step1(BACKEND_DIRECT, ITERATIONS)
    results["login_mfa_step1"] = stats(t_mfa_s1)

    # ── 3. Verificare JWT per cerere ─────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  [3] OVERHEAD JWT — GET /profile (fiecare cerere protejata)")
    print(SEP)
    if access_token:
        t_jwt = bench_profile(BACKEND_DIRECT, access_token, ITERATIONS * 2)
        results["jwt_verify"] = stats(t_jwt)
    else:
        print("  SARIT (nu exista access token)")
        results["jwt_verify"] = {}

    # ── 4. Verificare TOTP (endpoint timing) ────────────────────────────────
    print(f"\n{SEP}")
    print(f"  [4] LATENTA ENDPOINT TOTP VERIFY (cod invalid, sub rate limit)")
    print(SEP)
    t_totp = bench_totp_invalid(BACKEND_DIRECT, temp_token, 4)
    results["totp_verify"] = stats(t_totp)

    # ── 5. FIDO2 server-side ─────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  [5] LATENTA ENDPOINT FIDO2 VERIFY (credential fals, server-side)")
    print(SEP)
    t_fido2 = bench_fido2_server_side(BACKEND_DIRECT, access_token, 5)
    results["fido2_verify"] = stats(t_fido2)

    # ── 6. Direct vs Proxy ───────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  [6] OVERHEAD MITMPROXY — direct vs prin proxy")
    print(SEP)
    t_direct, t_proxy = bench_direct_vs_proxy(5)
    results["direct_backend"] = stats(t_direct)
    results["mitm_proxy"]     = stats(t_proxy)

    # ── SUMAR ─────────────────────────────────────────────────────────────────
    print(f"\n{SEP2}")
    print("  SUMAR — LATENTA PE ETAPE DE SECURITATE")
    print(SEP2)
    print_stats("Login fara MFA (baseline)",         results["login_no_mfa"])
    print_stats("Login cu MFA pasul 1 (parola)",     results["login_mfa_step1"])
    print_stats("Verificare JWT (per cerere)",        results["jwt_verify"])
    print_stats("Endpoint TOTP verify (server-side)",  results["totp_verify"])
    print_stats("Endpoint FIDO2 verify (server-side)", results.get("fido2_verify", {}))
    print(SEP)
    print_stats("Login direct la backend",            results["direct_backend"])
    if results["mitm_proxy"]:
        print_stats("Login prin mitmproxy",           results["mitm_proxy"])
        s_d = results["direct_backend"]
        s_p = results["mitm_proxy"]
        if s_d and s_p:
            overhead = s_p["mean"] - s_d["mean"]
            print(f"\n  Overhead mitmproxy (interceptare): +{overhead:.1f}ms medie")

    print(SEP)

    # Calculeaza latenta totala estimata cu MFA
    s1 = results.get("login_mfa_step1", {})
    s2 = results.get("totp_verify", {})
    if s1 and s2:
        total_mfa = s1["mean"] + s2["mean"]
        baseline  = results.get("login_no_mfa", {}).get("mean", 0)
        overhead  = total_mfa - baseline
        print(f"\n  OVERHEAD MFA (estimat):")
        print(f"    Login fara MFA         : {baseline:.1f}ms")
        print(f"    Login cu MFA (2 pasi)  : {total_mfa:.1f}ms  "
              f"(pasul1={s1['mean']:.1f}ms + TOTP={s2['mean']:.1f}ms)")
        print(f"    Overhead adaugat de MFA: +{overhead:.1f}ms per autentificare")
        print(f"    Overhead JWT per cerere: {results.get('jwt_verify', {}).get('mean', 0):.1f}ms")
        print(f"\n  Nota: la autentificarea FIDO2, pasul 2 include si")
        print(f"  verificare criptografica a semnaturii (Ed25519/ES256),")
        print(f"  adaugand ~2-5ms fata de TOTP (estimat din literatura).")

    print(f"{SEP2}\n")


if __name__ == "__main__":
    main()
