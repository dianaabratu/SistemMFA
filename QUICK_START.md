# Ghid de pornire rapidă

## Cerințe

- Node.js >= 18
- PostgreSQL >= 14
- Python >= 3.10 (pentru scripturile de atac)
- mitmproxy (opțional, pentru demo MitM)

---

## 1. Configurare bază de date

```powershell
psql -U postgres
```

```sql
CREATE DATABASE mfa_auth_db;
\c mfa_auth_db
\i database/schema.sql
\q
```

---

## 2. Configurare backend

```powershell
cd backend
cp .env.example .env
npm install
```

Editează `backend/.env`:

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=mfa_auth_db
DB_USER=postgres
DB_PASSWORD=parola_ta_postgres

JWT_SECRET=cheie_secreta_min_32_caractere
JWT_REFRESH_SECRET=alta_cheie_secreta_min_32_caractere

GOOGLE_CLIENT_ID=id_din_google_cloud_console
GOOGLE_CLIENT_SECRET=secret_din_google_cloud_console
GOOGLE_CALLBACK_URL=http://localhost:5000/api/v1/auth/google/callback

CORS_ORIGIN=http://localhost:3000
PORT=5000
NODE_ENV=development
API_VERSION=v1
```

> Google OAuth e opțional pentru testare de bază — autentificarea cu email/parolă funcționează fără el.

---

## 3. Configurare frontend

```powershell
cd frontend
npm install
```

Frontend-ul folosește Vite cu proxy configurat în `vite.config.js`. Nu necesită `.env` separat.

---

## 4. Pornire aplicație

Ordinea contează — backend-ul trebuie să fie activ înainte de frontend.

**Terminal 1 — Backend:**
```powershell
cd backend
npm start
```

Confirmare pornire:
```
Server MFA pornit pe portul 5000
```

**Terminal 2 — Frontend:**
```powershell
cd frontend
npm run dev
```

Aplicația e accesibilă la `http://localhost:3000`.

---

## 5. Conturi de test

| Email | Parolă | MFA |
|---|---|---|
| `test@example.com` | `Test123!@#` | TOTP activ |
| `test.jwt@example.com` | `Test123!@#` | Fără MFA |

---

## 6. Scenarii de atac

Scripturile rulează direct la backend (port 5000). Asigură-te că backend-ul e pornit.

```powershell
cd attack_scripts

python 01_brute_force_login.py       # Brute force login
python 02_brute_force_totp.py        # Brute force TOTP
python 03_totp_replay.py             # Replay attack (necesită cod din Google Authenticator)
python 04_jwt_tampering.py           # Modificare JWT
python 06_fido2_origin_binding.py    # Origin binding FIDO2
python 07_latency_benchmark.py       # Benchmark latență
```

> Dacă primești eroare 429 (prea multe încercări), repornește backend-ul pentru a reseta rate limiter-ul.

---

## 7. Demo MitM HTTP (opțional)

Demonstrează interceptarea traficului HTTP necriptat.

**Pornire în ordinea:**

**Terminal 1 — Backend** (deja pornit)

**Terminal 2 — mitmproxy:**
```powershell
cd mitm_demo
C:\Users\Diana\AppData\Roaming\Python\Python310\Scripts\mitmweb.exe `
  -s mitm_mfa_demo.py `
  --mode reverse:http://localhost:5000 `
  --listen-port 8085 `
  --web-port 8083
```

**Terminal 3 — Frontend** (după mitmproxy):
```powershell
cd frontend
npm run dev
```

Interfața mitmproxy: `http://127.0.0.1:8083`

Autentifică-te din browser — credențialele, codurile TOTP și JWT-urile vor apărea interceptate în interfața mitmproxy și în terminal.

> Vite este configurat să trimită cererile `/api` prin mitmproxy (port 8085) în loc de direct la backend (port 5000). Pentru a reveni la modul normal, oprește mitmproxy și repornește frontend-ul.

---

## Troubleshooting

**429 — Prea multe încercări de autentificare**  
Rate limiter-ul e în memorie. Repornește backend-ul.

**Port 5000 ocupat**  
Schimbă `PORT=5001` în `backend/.env` și actualizează target-ul din `vite.config.js`.

**Nu apar flow-uri în mitmproxy**  
Vite trebuie repornit după ce mitmproxy e activ.

**Eroare bază de date**  
Verifică că PostgreSQL rulează și că `DB_PASSWORD` din `.env` e corect.
```powershell
# Verificare serviciu PostgreSQL pe Windows
Get-Service postgresql*
```
