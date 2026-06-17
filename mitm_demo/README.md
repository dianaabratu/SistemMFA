# Demo Man-in-the-Middle — Interceptare trafic HTTP

## Context academic

Această demonstrație ilustrează vulnerabilitatea autentificării MFA transmise prin HTTP necriptat. Un atacator poziționat între client și server poate intercepta credențiale, coduri TOTP și token-uri JWT în text clar.

**Limitare importantă:** demonstrația folosește un proxy invers local (nu un atac real în rețea). Într-un scenariu real, atacatorul ar folosi ARP poisoning sau DNS spoofing pentru a redirecționa traficul. Efectul asupra datelor transmise este identic — dacă nu există HTTPS, datele sunt expuse.

---

## Arhitectura demonstrației

```
Browser
  │
  ▼
Vite dev server (:3000)          ← proxy server-side (Node.js)
  │   /api/* →
  ▼
mitmproxy (:8085)                ← interceptează și loghează
  │   → forward
  ▼
Backend Express (:5000)          ← procesează cererea normal
```

Vite proxy-ul e folosit deoarece browserele blochează configurarea proxy-ului manual pentru adrese loopback (`localhost`). Cererile API trec prin procesul Node.js, care nu are această restricție.

---

## Pornire

**Ordinea contează.**

**Terminal 1 — Backend:**
```powershell
cd backend
npm start
```

**Terminal 2 — mitmproxy:**
```powershell
cd mitm_demo
C:\Users\Diana\AppData\Roaming\Python\Python310\Scripts\mitmweb.exe `
  -s mitm_mfa_demo.py `
  --mode reverse:http://localhost:5000 `
  --listen-port 8085 `
  --web-port 8083
```

**Terminal 3 — Frontend** (după ce mitmproxy e activ):
```powershell
cd frontend
npm run dev
```

Interfața web mitmproxy: `http://127.0.0.1:8083`

---

## Ce interceptează scriptul

### Login cu email și parolă
```
CREDENTIALE INTERCEPTATE
  Email   : utilizator@example.com
  Parola  : ParolaInClar123!
```
Credențialele sunt vizibile în corpul cererii HTTP POST — orice proxy sau sniffer le poate citi.

### Verificare TOTP
```
COD TOTP INTERCEPTAT
  Cod TOTP    : 482917
  Temp Token  : eyJhbGciOiJIUzI1NiIs...
  Valid ~30s  — incerc replay automat...
```
Scriptul încearcă automat să refolosească codul capturat după 2 secunde (replay attack). Sistemul blochează al doilea usage cu 401.

### Răspuns login reușit
```
JWT TOKEN INTERCEPTAT
  Access Token : eyJhbGciOiJIUzI1NiIs...
  Refresh Token: eyJhbGciOiJIUzI1NiIs...
  Expira in   : 15 minute
```
Token-ul JWT capturat poate fi folosit direct pentru a accesa resurse protejate fără autentificare.

### Cerere FIDO2/WebAuthn
```
[FIDO2] Raspuns WebAuthn interceptat
  clientDataJSON decodat:
    type      : webauthn.get
    origin    : http://localhost:3000
    challenge : Xt7mK9...
  DE CE NU POATE FI REFOLOSIT:
  1. challenge-ul e unic per sesiune — replay respins
  2. origin din clientDataJSON e semnat criptografic
  3. cheia privata nu paraseste niciodata autentificatorul
```
Datele FIDO2 sunt vizibile în transit, dar sunt inutilizabile — cheia privată nu a fost transmisă niciodată.

---

## Concluzii comparative

| Scenariu | HTTP (fără TLS) | HTTPS (cu TLS) |
|---|---|---|
| Credențiale login | Vizibile în clar | Criptate |
| Cod TOTP | Vizibil, reutilizabil 30s | Criptat |
| JWT token | Vizibil, reutilizabil | Criptat |
| Date FIDO2 | Vizibile, dar inutilizabile | Criptate + inutilizabile |

**FIDO2** este singura metodă MFA care rămâne rezistentă la interceptare chiar și pe HTTP, datorită legăturii criptografice dintre credential și origin. TOTP și parolele necesită obligatoriu HTTPS pentru a fi protejate.

---

## Revenire la modul normal

Oprește mitmproxy (Ctrl+C) și repornește frontend-ul — Vite va trimite cererile direct la backend (port 5000).
