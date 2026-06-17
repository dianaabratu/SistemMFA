"""
Simulare Brute Force pe verificarea TOTP
=========================================
Pasul 1: Login cu email+parola pentru a obtine un tempToken valid.
Pasul 2: Incercare repetata de coduri TOTP pentru a declansa rate limiting.

Rulare:
    python 02_brute_force_totp.py
"""

import urllib.request
import urllib.error
import json
import time

BASE         = "http://localhost:5000/api/v1"
LOGIN_URL    = f"{BASE}/auth/login"
TOTP_URL     = f"{BASE}/auth/mfa/totp/verify"

EMAIL    = "test@example.com"
PASSWORD = "Test123!@#"

SEP  = "-" * 55
SEP2 = "=" * 55

# Coduri TOTP de incercat (simulam un atac secvential)
# TOTP real are 1.000.000 combinatii (000000-999999)
# Demonstram ca rate limiting-ul blocheaza mult inainte
TOTP_ATTEMPTS = [f"{i:06d}" for i in range(100, 115)]

def post(url, body, token=None):
    payload = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = {}
        try:
            body = json.loads(e.read())
        except Exception:
            pass
        return e.code, body
    except Exception as ex:
        return 0, {"message": str(ex)}

def get_temp_token():
    print(f"  Autentificare cu {EMAIL}...")
    status, body = post(LOGIN_URL, {"email": EMAIL, "password": PASSWORD})
    if status == 200 and body.get("requireMFA"):
        token = body.get("tempToken")
        print(f"  tempToken obtinut: {token[:40]}...")
        return token
    elif status == 0:
        print(f"  EROARE: Backend-ul nu ruleaza ({body.get('message', '')})")
        return None
    else:
        print(f"  EROARE la login: {status} - {body.get('message', '')}")
        return None

def main():
    print(f"\n{SEP2}")
    print("  SIMULARE BRUTE FORCE - TOTP")
    print(SEP2)
    print(f"  Tinta  : {TOTP_URL}")
    print(f"  Cont   : {EMAIL}")
    print(f"  Coduri : {len(TOTP_ATTEMPTS)} incercari ({TOTP_ATTEMPTS[0]} - {TOTP_ATTEMPTS[-1]})")
    print(f"  Nota   : TOTP are 1.000.000 combinatii posibile (000000-999999)")
    print(f"{SEP2}\n")

    temp_token = get_temp_token()
    if not temp_token:
        print("\n  Opreste scriptul - nu s-a putut obtine tempToken.")
        return

    print(f"\n{SEP}")
    print("  Incepe atacul TOTP...")
    print(SEP)

    blocked    = False
    blocked_at = None

    for i, code in enumerate(TOTP_ATTEMPTS, 1):
        status, body = post(TOTP_URL, {"token": code, "method": "totp"}, temp_token)
        message = body.get("message", "")

        if status == 200:
            print(f"  [{i:02d}] COD GASIT: {code} -> Autentificare reusita!")
            print(f"       JWT: {body.get('accessToken', '')[:40]}...")
            break
        elif status == 401:
            print(f"  [{i:02d}] Incorect: {code} -> {message}")
        elif status == 429:
            if not blocked:
                blocked    = True
                blocked_at = i
            print(f"  [{i:02d}] BLOCAT (429): {message}")
            if i == blocked_at:
                print(f"\n{SEP}")
                print(f"  [OK] Rate limiting activat dupa {i} incercari!")
                print(f"  Atacatorul trebuie sa astepte 15 minute.")
                print(f"  La 5 incercari / 15 min, testarea completa")
                print(f"  a tuturor codurilor ar dura ~138 de zile!")
                print(SEP)
        else:
            print(f"  [{i:02d}] Status {status}: {message}")

        time.sleep(0.2)

    print(f"\n{SEP2}")
    print("  SUMAR")
    print(SEP2)
    if blocked:
        print(f"  Rate limiting activat la incercarea #{blocked_at}")
        print(f"  Coduri testate inainte de blocare: {blocked_at - 1}")
        print(f"  Combinatii posibile TOTP: 1.000.000 ~138 zile")
        print(f"  Concluzie: brute force pe TOTP imposibil. [OK]")
    else:
        print(f"  Rate limiting nu s-a activat in {len(TOTP_ATTEMPTS)} incercari.")
        print(f"  Verifica configuratia rate limiter-ului pe /auth.")
    print(f"{SEP2}\n")

if __name__ == "__main__":
    main()
