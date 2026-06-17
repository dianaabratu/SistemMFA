# Sistem de Autentificare Multifactor (MFA)

**Lucrare de disertatie -- Diana-Roxana Bratu**

Tema: Metode de autentificare multifactor pentru securitatea retelelor

---

## Descriere

Sistem complet de autentificare multifactor implementat ca aplicatie web, cu scopul de a compara metodele MFA din perspectiva securitatii, utilizabilitatii si performantei. Proiectul include implementarea sistemului si un set de scenarii de atac simulate pentru evaluarea rezilentei.

---

## Stiva tehnologica

| Strat | Tehnologii |
|---|---|
| Frontend | React 18, Vite, React Router v6, Axios, Bootstrap 5 |
| Backend | Node.js 18+, Express 4, JWT, bcryptjs, speakeasy, fido2-lib |
| Baza de date | PostgreSQL 14+ |
| Autentificare externa | Google OAuth 2.0 / OpenID Connect |
| Securitate HTTP | Helmet.js, express-rate-limit, CORS |
| Demo atacuri | Python 3.10+, mitmproxy |

---

## Metode MFA implementate

| Metoda | Standard |
|---|---|
| TOTP (Google Authenticator) | RFC 6238 |
| FIDO2 / WebAuthn | FIDO Alliance |
| Coduri de backup | hash bcrypt, single-use |
| Google OAuth 2.0 | OpenID Connect |

---

## Structura proiectului

```
mfa-auth-system/
├── backend/
│   └── src/
│       ├── controllers/
│       ├── models/
│       ├── routes/
│       ├── middleware/
│       ├── utils/
│       └── server.js
├── frontend/
│   └── src/
│       ├── pages/
│       ├── context/
│       └── services/
├── database/
│   └── schema.sql
├── mitm_demo/
│   └── mitm_mfa_demo.py
├── attack_scripts/
│   ├── 01_brute_force_login.py
│   ├── 02_brute_force_totp.py
│   ├── 03_totp_replay.py
│   ├── 06_fido2_origin_binding.py
│   └── 07_latency_benchmark.py
└── QUICK_START.md
```

---

## Scenarii de atac simulate

| Script | Atac simulat | Rezultat asteptat |
|---|---|---|
| 01_brute_force_login.py | Brute force login | Blocat dupa 5 incercari (429) |
| 02_brute_force_totp.py | Brute force TOTP | Blocat dupa 5 incercari (429) |
| 03_totp_replay.py | Refolosire cod interceptat | Blocat (401) |
| 06_fido2_origin_binding.py | Credential fals alt origin | Respins (400) |
| 07_latency_benchmark.py | Masurare latenta mecanisme | Raport statistici |

Demo MitM HTTP (`mitm_demo/mitm_mfa_demo.py`): traficul HTTP trece prin mitmproxy care intercepteaza credentiale, coduri TOTP si JWT in clar.

---

## Comparatie metode MFA

| Criteriu | TOTP | FIDO2 |
|---|---|---|
| Rezistenta phishing | Partiala | Completa (origin binding) |
| Rezistenta MitM HTTP | Vulnerabil | Rezistent |
| Rezistenta replay | Partiala (30s) | Completa (challenge unic) |
| Necesita hardware | Nu | Optional |

---

## Pornire rapida

```
# Terminal 1 - Backend
cd backend
npm start

# Terminal 2 - Frontend
cd frontend
npm run dev
```

Vezi QUICK_START.md pentru instructiuni complete.

---

## Autor

**Diana-Roxana Bratu** -- Lucrare de disertatie, 2026

Facultatea de Electronica, Telecomunicatii si Tehnologia Informatiei