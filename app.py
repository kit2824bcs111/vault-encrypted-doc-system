from dotenv import load_dotenv
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from functools import wraps
import sqlite3
import secrets
from crypto_utils import encrypt_data, decrypt_data, generate_key
load_dotenv()
# ── App Setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)
DB_PATH = "vault.db"


# ── Database Helpers ───────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT UNIQUE NOT NULL,
            password_hash   TEXT NOT NULL,
            encryption_key  TEXT NOT NULL,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id           INTEGER NOT NULL,
            title             TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            username    TEXT,
            action      TEXT NOT NULL,
            details     TEXT,
            ip_address  TEXT,
            timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def log_action(user_id, username, action, details=""):
    """Write an entry to the audit log."""
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
        (user_id, username, action, details, request.remote_addr),
    )
    conn.commit()
    conn.close()


# ── Auth Decorator ─────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            flash("Both fields are required.", "error")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("register.html")

        conn = get_db()
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("Username already taken.", "error")
            conn.close()
            return render_template("register.html")

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        encryption_key = generate_key()  # unique AES-256 key per user

        conn.execute(
            "INSERT INTO users (username, password_hash, encryption_key) VALUES (?, ?, ?)",
            (username, password_hash, encryption_key),
        )
        conn.commit()
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        log_action(user["id"], username, "REGISTER", "New account created")
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_action(user["id"], username, "LOGIN", "Successful login")
            return redirect(url_for("dashboard"))
        else:
            log_action(None, username, "LOGIN_FAILED", f"Bad credentials for '{username}'")
            flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    log_action(session.get("user_id"), session.get("username"), "LOGOUT", "User logged out")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    docs = conn.execute(
        "SELECT id, title, created_at FROM documents WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", documents=docs, username=session["username"])


@app.route("/document/add", methods=["GET", "POST"])
@login_required
def add_document():
    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"].strip()

        if not title or not content:
            flash("Title and content are required.", "error")
            return render_template("add_document.html")

        conn = get_db()
        user = conn.execute("SELECT encryption_key FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        encrypted = encrypt_data(content, user["encryption_key"])

        conn.execute(
            "INSERT INTO documents (user_id, title, encrypted_content) VALUES (?, ?, ?)",
            (session["user_id"], title, encrypted),
        )
        conn.commit()
        conn.close()

        log_action(session["user_id"], session["username"], "ADD_DOCUMENT", f"Stored: '{title}'")
        flash("Document encrypted and stored successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_document.html")


@app.route("/document/<int:doc_id>")
@login_required
def view_document(doc_id):
    conn = get_db()
    doc = conn.execute(
        "SELECT * FROM documents WHERE id = ? AND user_id = ?",
        (doc_id, session["user_id"]),
    ).fetchone()

    if not doc:
        flash("Document not found or access denied.", "error")
        conn.close()
        return redirect(url_for("dashboard"))

    user = conn.execute("SELECT encryption_key FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()

    decrypted_content = decrypt_data(doc["encrypted_content"], user["encryption_key"])
    log_action(session["user_id"], session["username"], "VIEW_DOCUMENT", f"Decrypted: '{doc['title']}'")

    return render_template("view_document.html", doc=doc, content=decrypted_content)


@app.route("/document/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    conn = get_db()
    doc = conn.execute(
        "SELECT title FROM documents WHERE id = ? AND user_id = ?",
        (doc_id, session["user_id"]),
    ).fetchone()

    if doc:
        conn.execute("DELETE FROM documents WHERE id = ? AND user_id = ?", (doc_id, session["user_id"]))
        conn.commit()
        log_action(session["user_id"], session["username"], "DELETE_DOCUMENT", f"Deleted: '{doc['title']}'")
        flash("Document deleted.", "success")

    conn.close()
    return redirect(url_for("dashboard"))


@app.route("/audit")
@login_required
def audit():
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return render_template("audit.html", logs=logs, username=session["username"])


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print(" Database initialised.")
    print(" Vault running at http://127.0.0.1:5000")
    app.run(debug=True)
