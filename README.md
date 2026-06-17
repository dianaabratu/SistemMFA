# Sistem de Autentificare Multifactor (MFA)

**Lucrare de disertație — Diana-Roxana Bratu**  
Tema: Metode de autentificare multifactor pentru securitatea rețelelor  

---

## Descriere

Sistem complet de autentificare multifactor implementat ca aplicație web, cu scopul de a compara metodele MFA din perspectiva securității, utilizabilității și performanței. Proiectul include atât implementarea sistemului, cât și un set de scenarii de atac simulate pentru evaluarea rezilienței.

---

## Arhitectură

```
┌──────────────┐       ┌──────────────────┐       ┌─────────────┐
│  React 18    │──────▶│  Node.js/Express │──────▶│ PostgreSQL  │
│  Vite        │◀──────│  REST API        │◀──────│             │
│  :3000       │       │  :5000           │       └─────────────┘
└──────────────┘       └──────────────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
      Google OAuth 2.0       TOTP           FIDO2/WebAuthn
      (OpenID Connect)   (speakeasy,        (autentificator
      autentificare       RFC 6238,          hardware/soft,
      externă)           self-contained)     origin binding)
```

**Demo MitM (HTTP):**
```
Browser → Vite proxy (:3000) → mitmproxy (:8085) → Backend (:5000)
```

---

## Tehnologii

| Strat | Tehnologii |
|---|---|
| Frontend | React 18, Vite, React Router v6, Axios, Bootstrap 5 |
| Backend | Node.js 18+, Express 4, JWT, bcryptjs, speakeasy, fido2-lib |
| Bază de date | PostgreSQL 14+ |
| Autentificare externă | Google OAuth 2.0 / OpenID Connect |
| Securitate HTTP | Helmet.js, express-rate-limit, CORS |
| Demo atacuri | Python 3.10+, mitmproxy |

---

## Funcționalități implementate

### Autentificare
- Înregistrare cu email/parolă (bcrypt, 12 rounds)
- Autentificare Google (OAuth 2.0 / OIDC)
- JWT cu access token (15 min) + refresh token (7 zile)
- Flux în doi pași: credențiale → MFA

### Metode MFA
| Metodă | Status | Standard |
|---|---|---|
| TOTP (Google Authenticator) | Implementat | RFC 6238 |
| FIDO2 / WebAuthn | Implementat | FIDO Alliance |
| Coduri de backup | Implementat | hash bcrypt, single-use |

### Securitate
- Rate limiting: 5 încercări eșuate / 15 min / IP
- Audit log pentru toate acțiunile de autentificare
- Coduri de backup hash-uite cu bcrypt (nu stocate în clar)
- FIDO2 origin binding (rezistent la phishing și MitM)
- Protecție SQL injection prin query-uri parametrizate
- Headers de securitate (Helmet.js)

---

## Structura proiectului

```
mfa-auth-system/
├── backend/
│   └── src/
│       ├── controllers/     # authController.js, mfaController.js
│       ├── models/          # User.js, MFA.js
│       ├── routes/          # authRoutes.js, mfaRoutes.js
│       ├── middleware/      # auth.js (verificare JWT)
│       ├── utils/           # auditLogger.js
│       └── server.js
├── frontend/
│   └── src/
│       ├── pages/           # LoginPage, RegisterPage, DashboardPage,
│       │                    # MFASetupPage, MFAVerifyPage, AttackDemoPage
│       ├── context/         # AuthContext.jsx
│       └── services/        # api.js (Axios + interceptori JWT)
├── database/
│   └── schema.sql
├── mitm_demo/
│   └── mitm_mfa_demo.py     # Addon mitmproxy — interceptare HTTP
├── attack_scripts/
│   ├── 01_brute_force_login.py      # Brute force + rate limiting
│   ├── 02_brute_force_totp.py       # Brute force TOTP + rate limiting
│   ├── 03_totp_replay.py            # Replay attack TOTP
│   ├── 04_jwt_tampering.py          # Modificare payload JWT
│   ├── 06_fido2_origin_binding.py   # Origin binding FIDO2
│   └── 07_latency_benchmark.py      # Benchmark latență mecanisme MFA
└── QUICK_START.md
```

---

## API — Endpoints principale

**Base URL:** `http://localhost:5000/api/v1`

### Autentificare

| Metodă | Endpoint | Descriere |
|---|---|---|
| POST | `/auth/register` | Înregistrare utilizator nou |
| POST | `/auth/login` | Login (returnează JWT sau tempToken dacă MFA activ) |
| POST | `/auth/logout` | Invalidare refresh token |
| GET  | `/auth/profile` | Profil utilizator (necesită JWT) |
| GET  | `/auth/audit-logs` | Jurnal acțiuni (necesită JWT) |
| GET  | `/auth/google` | Inițiere flux Google OAuth |
| GET  | `/auth/google/callback` | Callback Google OAuth |

### Verificare MFA (necesită `tempToken`)

| Metodă | Endpoint | Descriere |
|---|---|---|
| POST | `/auth/mfa/totp/verify` | Verificare cod TOTP |
| POST | `/auth/mfa/backup-code/verify` | Verificare cod de backup |
| GET  | `/auth/mfa/fido2/options` | Challenge WebAuthn |
| POST | `/auth/mfa/fido2/verify` | Verificare răspuns WebAuthn |

### Configurare MFA (necesită `accessToken`)

| Metodă | Endpoint | Descriere |
|---|---|---|
| GET  | `/mfa/methods` | Lista metode active |
| POST | `/mfa/setup/totp` | Generare secret TOTP + QR |
| POST | `/mfa/setup/totp/confirm` | Confirmare configurare TOTP |
| GET  | `/mfa/setup/fido2/options` | Options înregistrare FIDO2 |
| POST | `/mfa/setup/fido2/complete` | Finalizare înregistrare FIDO2 |
| POST | `/mfa/enable` | Activare MFA |
| POST | `/mfa/disable` | Dezactivare MFA |
| POST | `/mfa/backup-codes/:method` | Generare coduri de backup |

---

## Scenarii de atac simulate

Scripturile din `attack_scripts/` demonstrează reziliența sistemului:

| Script | Atac simulat | Rezultat așteptat |
|---|---|---|
| `01_brute_force_login.py` | 10+ încercări login | Blocat după 5 (429) |
| `02_brute_force_totp.py` | Ghicire cod TOTP | Blocat după 5 (429) |
| `03_totp_replay.py` | Refolosire cod interceptat | Blocat (401) |
| `06_fido2_origin_binding.py` | Credential fals alt origin | Respins (400) |
| `07_latency_benchmark.py` | Măsurare latență mecanisme | Raport statistici |

**Demo MitM HTTP** (`mitm_demo/mitm_mfa_demo.py`):  
Traficul HTTP trece prin mitmproxy, care interceptează credențiale, coduri TOTP și JWT în clar — demonstrând necesitatea HTTPS în producție.

---

## Securitate — concluzii comparative

| Criteriu | TOTP | FIDO2 |
|---|---|---|
| Rezistență phishing | Parțială (cod poate fi copiat) | Completă (origin binding) |
| Rezistență MitM HTTP | Vulnerabil (cod vizibil) | Rezistent (semnătură criptografică) |
| Rezistență replay | Parțială (30s fereastră) | Completă (challenge unic) |
| Necesită hardware | Nu | Opțional |
| Ușurință configurare | Mare | Medie |

---

## Pornire aplicație

Vezi [QUICK_START.md](QUICK_START.md) pentru instrucțiuni detaliate.

```bash
# Terminal 1 — Backend
cd backend && npm start

# Terminal 2 — Frontend
cd frontend && npm run dev
```

---

## Autor

**Diana-Roxana Bratu** — Lucrare de disertație, 2026  
Facultatea de Electronică, Telecomunicații și Tehnologia Informației
