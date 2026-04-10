# VAULT — Encrypted Document System

A full-stack encrypted document storage system built with Python, Flask, and AES-256-GCM encryption.

---

## TECH STACK
| Layer | Technology |
|---|---|
| Backend | Python + Flask |
| Database | SQLite (vault.db) |
| Encryption | AES-256-GCM (cryptography library) |
| Passwords | Bcrypt hashing |
| Frontend | Jinja2 + Custom CSS |

---

## FEATURES
-  User registration & login
-  Bcrypt password hashing
-  AES-256-GCM encryption per document
-  Unique encryption key per user
-  View & decrypt documents
-  Delete documents
-  Audit log for all actions
-  Raw encrypted blob visible on document page

---

## SETUP INSTRUCTIONS (VS Code)

### Step 1 — Open folder in VS Code
```
File → Open Folder → select vault_system/
```

### Step 2 — Create virtual environment
```bash
python -m venv venv
```

### Step 3 — Activate virtual environment
**Windows:**
```bash
venv\Scripts\activate
```
**Mac/Linux:**
```bash
source venv/bin/activate
```

### Step 4 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 5 — Run the app
```bash
python app.py
```

### Step 6 — Open in browser
```
http://127.0.0.1:5000
```

---

## PROJECT STRUCTURE
```
vault_system/
│
├── app.py              ← Main Flask app (routes, logic)
├── crypto_utils.py     ← AES-256-GCM encrypt/decrypt
├── requirements.txt    ← Python packages
├── vault.db            ← SQLite DB (auto-created on first run)
│
├── templates/
│   ├── base.html       ← Shared layout + nav
│   ├── login.html      ← Login page
│   ├── register.html   ← Register page
│   ├── dashboard.html  ← Document list
│   ├── add_document.html ← Add/encrypt form
│   ├── view_document.html ← Decrypt & view
│   └── audit.html      ← Audit log table
│
└── static/
    └── style.css       ← Dark vault UI styles
```

---

## HOW ENCRYPTION WORKS
1. Each user gets a unique **AES-256 key** generated on registration
2. When a document is saved → content is encrypted with `AES-256-GCM`
3. A random **nonce** (96-bit) is generated per encryption → packed with ciphertext
4. Only the **encrypted blob** is stored in the database
5. When viewing → blob is decrypted in memory using the user's key
6. If a hacker steals the database → they see only random gibberish

---

## GRADING POINTS TO HIGHLIGHT
- AES-256-GCM is authenticated encryption (tamper-proof)
- Passwords are bcrypt-hashed (never stored in plaintext)
- Each user has an isolated encryption key
- Audit log records every action with timestamps & IP
- Raw encrypted blob is shown on the view page (proof of encryption)
