"""
Simulare Brute Force pe endpoint-ul de login
Demonstreaza ca rate limiting-ul blocheaza atacul dupa 5 incercari.

Rulare:
    python 01_brute_force_login.py
"""

import urllib.request
import urllib.error
import json
import time

TARGET       = "http://localhost:5000/api/v1/auth/login"
TARGET_EMAIL = "diana.licenta2024@gmail.com"

PASSWORDS = [
    "password", "123456", "qwerty", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "parola123",
    "Password1", "abc123!", "Test1234", "Summer2024!",
    "Diana2024!", "Licenta2024!", "iloveyou", "sunshine",
    "princess", "football", "charlie", "donald", "batman",
    "shadow", "superman", "michael", "jessica", "login",
    "passw0rd", "p@ssword", "test1234", "hello123",
    "Pa$$word", "secret", "abc1234!", "winter2024",
    "spring24", "romania1", "student01", "licenta01",
    "disertatie", "secure123", "pass1234!", "root1234",
    "toor1234", "admin123!", "user1234", "test@123",
    "Test123!@#", "Admin2024!", "Pass2024!", "Qwerty123!",
    "Parola123!", "Romania2024!", "Disertatie1!", "Final2024!"
]

SEP  = "-" * 55
SEP2 = "=" * 55

def send_request(email, password):
    payload = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(
        TARGET,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
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

def main():
    print(f"\n{SEP2}")
    print("  SIMULARE BRUTE FORCE - LOGIN")
    print(SEP2)
    print(f"  Tinta  : {TARGET}")
    print(f"  Email  : {TARGET_EMAIL}")
    print(f"  Parole : {len(PASSWORDS)} incercari")
    print(f"{SEP2}\n")

    blocked    = False
    blocked_at = None

    for i, password in enumerate(PASSWORDS, 1):
        status, body = send_request(TARGET_EMAIL, password)
        message = body.get("message", "")

        if status == 200:
            print(f"  [{i:02d}] PAROLA GASITA: '{password}'")
            print(f"       Token: {body.get('accessToken', '')[:40]}...")
            break
        elif status == 401:
            print(f"  [{i:02d}] Incorecta: '{password}' -> {message}")
        elif status == 429:
            if not blocked:
                blocked    = True
                blocked_at = i
            print(f"  [{i:02d}] BLOCAT (429): {message}")
            if i == blocked_at:
                print(f"\n{SEP}")
                print(f"  [OK] Rate limiting activat dupa {i} incercari!")
                print(f"  Atacatorul este blocat temporar.")
                print(SEP)
        else:
            print(f"  [{i:02d}] Status {status}: {message}")

        time.sleep(0.3)

    print(f"\n{SEP2}")
    print("  SUMAR")
    print(SEP2)
    if blocked:
        print(f"  Rate limiting activat la incercarea #{blocked_at}")
        print(f"  Atacul a fost blocat inainte de a gasi parola.")
        print(f"  Concluzie: protectia functioneaza corect. [OK]")
    else:
        print(f"  Rate limiting nu a fost activat in {len(PASSWORDS)} incercari.")
        print(f"  Verifica configuratia backend-ului.")
    print(f"{SEP2}\n")

if __name__ == "__main__":
    main()
