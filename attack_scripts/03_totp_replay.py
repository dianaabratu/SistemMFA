"""
Simulare TOTP Replay Attack
============================
Scenariul: un atacator intercepteaza un cod TOTP valid (ex. prin sniffing HTTP)
si incearca sa il refoloseasca imediat, inainte de expirare (fereastra 30s).

Pasul 1: Login -> obtine tempToken
Pasul 2: Utilizatorul introduce manual un cod TOTP valid din Google Authenticator
Pasul 3: Scriptul trimite codul o data (prima autentificare)
Pasul 4: Scriptul retrimite imediat ACELASI cod (replay)
Pasul 5: Afiseaza daca replay-ul a reusit sau a fost blocat

Rulare:
    python 03_totp_replay.py
"""

import urllib.request
import urllib.error
import json
import time

BASE      = "http://localhost:5000/api/v1"
LOGIN_URL = f"{BASE}/auth/login"
TOTP_URL  = f"{BASE}/auth/mfa/totp/verify"

EMAIL    = "test@example.com"
PASSWORD = "Test123!@#"

SEP  = "-" * 55
SEP2 = "=" * 55

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
    status, body = post(LOGIN_URL, {"email": EMAIL, "password": PASSWORD})
    if status == 200 and body.get("requireMFA"):
        return body.get("tempToken")
    if status == 429:
        print(f"  EROARE: Rate limiting activ (429). Restarteaza backend-ul.")
    elif status == 200 and body.get("accessToken"):
        print(f"  EROARE: Contul {EMAIL} nu are MFA activ.")
    elif status == 401:
        print(f"  EROARE: Credentiale incorecte (401).")
    elif status == 0:
        print(f"  EROARE: Backend-ul nu raspunde. Pornit?")
    else:
        print(f"  EROARE: Status neasteptat {status} — {body.get('message', '')}")
    return None

def main():
    print(f"\n{SEP2}")
    print("  SIMULARE TOTP REPLAY ATTACK")
    print(SEP2)
    print(f"  Cont  : {EMAIL}")
    print(f"  Scenariu: atacatorul intercepteaza un cod TOTP si")
    print(f"            incearca sa il refoloseasca imediat.")
    print(f"{SEP2}\n")

    # Pas 1: obtine tempToken
    print("  [1] Login pentru obtinerea tempToken-ului...")
    temp_token = get_temp_token()
    if not temp_token:
        print("  EROARE: Nu s-a putut obtine tempToken. Backend pornit?")
        return
    print(f"  tempToken: {temp_token[:40]}...\n")

    # Pas 2: utilizatorul introduce codul din Google Authenticator
    print("  [2] Deschide Google Authenticator si introdu codul curent:")
    totp_code = input("      Cod TOTP (6 cifre): ").strip()
    if len(totp_code) != 6 or not totp_code.isdigit():
        print("  EROARE: Codul trebuie sa aiba exact 6 cifre.")
        return

    print(f"\n{SEP}")
    print(f"  Cod interceptat: {totp_code}")
    print(f"  Incepere replay attack...")
    print(SEP)

    # Pas 3: prima utilizare (victima se autentifica)
    print(f"\n  [3] Prima utilizare a codului (victima)...")
    t1 = time.time()
    status1, body1 = post(TOTP_URL, {"token": totp_code, "method": "totp"}, temp_token)
    elapsed1 = time.time() - t1

    if status1 == 200:
        print(f"  Rezultat: 200 OK - Autentificare reusita")
        print(f"  JWT obtinut: {body1.get('accessToken', '')[:40]}...")
    else:
        print(f"  Rezultat: {status1} - {body1.get('message', '')}")
        print(f"  (Codul era deja expirat sau incorect)")

    # Pas 4: replay imediat cu acelasi cod si acelasi tempToken
    print(f"\n  [4] Replay imediat cu ACELASI cod (atacatorul)...")
    print(f"  Timp de la prima utilizare: {elapsed1:.2f}s")
    time.sleep(0.5)

    status2, body2 = post(TOTP_URL, {"token": totp_code, "method": "totp"}, temp_token)

    print(f"  Rezultat replay: {status2} - {body2.get('message', '')}")

    # Pas 5: sumar
    print(f"\n{SEP2}")
    print("  SUMAR REPLAY ATTACK")
    print(SEP2)
    print(f"  Prima utilizare  : {status1} {'OK' if status1 == 200 else 'ESUAT'}")
    print(f"  Replay (imediat) : {status2} {'REUSIT - VULNERABILITATE!' if status2 == 200 else 'BLOCAT'}")
    print(SEP)

    if status2 == 200:
        print(f"\n  [!] VULNERABILITATE DETECTATA:")
        print(f"  Acelasi cod TOTP a fost acceptat de doua ori.")
        print(f"  Un atacator care intercepteaza codul (ex.HTTP)")
        print(f"  il poate reutiliza in fereastra de 30 de secunde.")
    else:
        print(f"\n  [OK] REPLAY BLOCAT:")
        if status2 == 429:
            print(f"  Rate limiting a blocat a doua cerere.")
        elif status2 == 401:
            print(f"  Codul a fost respins la a doua utilizare.")
        print(f"  Protectia impotriva replay functioneaza.")

    print(f"{SEP2}\n")

if __name__ == "__main__":
    main()
