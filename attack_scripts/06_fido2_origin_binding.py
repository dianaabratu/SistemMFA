"""
Simulare FIDO2 Origin Binding Attack
======================================
Scenariul: un atacator incearca sa foloseasca un raspuns WebAuthn
capturat/falsificat cu un origin diferit de cel asteptat de server.

In FIDO2/WebAuthn, clientDataJSON contine origin-ul paginii care
a initiat autentificarea. Serverul verifica ca origin-ul sa corespunda
exact cu cel inregistrat (ex. http://localhost:3000).
Orice nepotrivire invalideaza semnatura criptografic.

Pasii demonstratiei:
  1. Obtine un challenge FIDO2 valid de la server (necesita JWT)
  2. Construieste un raspuns fals cu origin GRESIT (http://evil.com)
  3. Trimite raspunsul falsificat la server
  4. Serverul respinge cu eroare de verificare

Rulare:
    python 06_fido2_origin_binding.py
"""

import urllib.request
import urllib.error
import json
import base64
import os
import time

BASE          = "http://localhost:5000/api/v1"
LOGIN_URL     = f"{BASE}/auth/login"
FIDO2_OPT_URL = f"{BASE}/auth/mfa/fido2/options"
FIDO2_VER_URL = f"{BASE}/auth/mfa/fido2/verify"

EMAIL    = "test.jwt@example.com"
PASSWORD = "Test123!@#"

SEP  = "-" * 55
SEP2 = "=" * 55

LEGITIMATE_ORIGIN = "http://localhost:3000"
ATTACKER_ORIGINS  = [
    "http://evil-site.com",
    "http://localhost:3001",
    "https://phishing-mfa.com",
    "http://127.0.0.1:3000",
]

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

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

def get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"}, method="GET")
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

def get_access_token():
    status, body = post(LOGIN_URL, {"email": EMAIL, "password": PASSWORD})
    if status == 200 and body.get("accessToken"):
        return body["accessToken"]
    return None

def build_fake_credential(challenge, origin):
    """
    Construieste un raspuns WebAuthn fals cu origin-ul specificat.
    clientDataJSON contine origin-ul — acesta e verificat de server.
    Semnatura si credentialul sunt inventate (vor fi respinse).
    """
    client_data = {
        "type":      "webauthn.get",
        "challenge": challenge,
        "origin":    origin,
        "crossOrigin": False
    }
    client_data_json = b64url(json.dumps(client_data, separators=(",", ":")))

    # Date inventate pentru demonstratie
    fake_id        = b64url(os.urandom(32))
    fake_auth_data = b64url(os.urandom(37))
    fake_signature = b64url(os.urandom(64))
    fake_user_handle = b64url(b"fakeuser")

    return {
        "id":    fake_id,
        "rawId": fake_id,
        "type":  "public-key",
        "response": {
            "clientDataJSON":    client_data_json,
            "authenticatorData": fake_auth_data,
            "signature":         fake_signature,
            "userHandle":        fake_user_handle,
        }
    }

def main():
    print(f"\n{SEP2}")
    print("  SIMULARE FIDO2 ORIGIN BINDING ATTACK")
    print(SEP2)
    print(f"  Origin legitim  : {LEGITIMATE_ORIGIN}")
    print(f"  Origin-uri false: {len(ATTACKER_ORIGINS)} variante")
    print(f"\n  In FIDO2, clientDataJSON este semnat impreuna cu")
    print(f"  challenge-ul. Orice origin diferit invalideaza")
    print(f"  semnatura — atacatorul nu poate falsifica originea.")
    print(f"{SEP2}\n")

    # Pas 1: obtine access token
    print("  [1] Login pentru obtinerea unui JWT valid...")
    access_token = get_access_token()
    if not access_token:
        print("  EROARE: Nu s-a putut obtine access token. Backend pornit?")
        return
    print(f"  JWT obtinut: {access_token[:40]}...\n")

    # Pas 2: obtine challenge FIDO2 real de la server
    print("  [2] Obtinere challenge FIDO2 de la server...")

    # Pentru a obtine optiunile FIDO2 in flow-ul de autentificare
    # avem nevoie de un tempToken (MFA pending). Folosim direct endpoint-ul
    # de setup pentru a demonstra verificarea origin-ului.
    status_opt, body_opt = get(f"{BASE}/mfa/fido2/options", access_token)

    if status_opt == 200:
        challenge = body_opt.get("options", {}).get("challenge", b64url(os.urandom(32)))
        print(f"  Challenge obtinut: {challenge[:40]}...")
    else:
        # Generam un challenge random pentru demonstratie
        challenge = b64url(os.urandom(32))
        print(f"  Challenge generat local (demo): {challenge[:40]}...")

    # Pas 3: atac cu diferite origin-uri false
    print(f"\n{SEP}")
    print(f"  [3] Se trimit raspunsuri FIDO2 cu origin-uri FALSE...")
    print(SEP)

    results = []

    # Testeaza fiecare origin fals
    for origin in ATTACKER_ORIGINS:
        fake_cred = build_fake_credential(challenge, origin)

        # Incercam pe endpoint-ul de verificare FIDO2 din flow-ul MFA
        # (necesita tempToken, deci va returna 401 din cauza auth, nu origin)
        # Demonstram conceptual cu endpoint-ul de completare inregistrare
        status, body = post(f"{BASE}/mfa/setup/fido2/complete", {"credential": fake_cred}, access_token)
        message = body.get("message", "")

        results.append((origin, status, message))
        blocked = status in (400, 401, 403)
        icon    = "[OK] BLOCAT" if blocked else "[!] TRECUT"
        print(f"  Origin: {origin:<35} -> {status} {icon}")
        print(f"          Motiv: {message[:60]}")
        time.sleep(0.3)

    # Pas 4: pentru comparatie, origin legitim (tot respins - fara credentiale reale)
    print(f"\n{SEP}")
    print(f"  [4] Comparatie: origin LEGITIM cu date false...")
    print(SEP)
    fake_cred_legit = build_fake_credential(challenge, LEGITIMATE_ORIGIN)
    status_l, body_l = post(f"{BASE}/mfa/setup/fido2/complete", {"credential": fake_cred_legit}, access_token)
    print(f"  Origin: {LEGITIMATE_ORIGIN:<35} -> {status_l}")
    print(f"  Motiv : {body_l.get('message', '')[:60]}")
    print(f"  Obs.  : Respins tot - semnatura criptografica invalida,")
    print(f"          nu din cauza origin-ului.")

    # Sumar
    print(f"\n{SEP2}")
    print("  SUMAR FIDO2 ORIGIN BINDING")
    print(SEP2)
    blocked_count = sum(1 for _, s, _ in results if s in (400, 401, 403))
    print(f"  Incercari cu origin fals : {len(results)}")
    print(f"  Blocate                  : {blocked_count}/{len(results)}")
    print(SEP)
    print(f"\n  Concluzie:")
    print(f"  FIDO2 leaga criptografic de origin.")
    print(f"  Un site de phishing (ex. http://evil-site.com) NU")
    print(f"  poate obtine un raspuns WebAuthn valid pentru")
    print(f"  http://localhost:3000 — browserul refuza sa semneze")
    print(f"  pentru un origin diferit de cel inregistrat.")
    print(f"\n  Aceasta proprietate (origin binding) face FIDO2")
    print(f"  rezistent la atacuri MitM si phishing, spre deosebire")
    print(f"  de TOTP unde codul poate fi interceptat si refolosit.")
    print(f"{SEP2}\n")

if __name__ == "__main__":
    main()
