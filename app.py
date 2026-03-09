from flask import Flask, render_template, request, redirect, url_for, session, Response
import os
import sqlite3
import random
import csv
import time
from datetime import datetime
from io import TextIOWrapper

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key_change_me")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "fraud.db")

ADMIN_ID = os.environ.get("ADMIN_ID", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "1234")

# Admin dashboard unlock key (Render Environment Variables)
ADMIN_GATE_KEY = os.environ.get("ADMIN_GATE_KEY", "thala123")

# Optional: Where to append new registered users CSV
CSV_USERS_PATH = os.path.join(BASE_DIR, "users.csv")


# ---------------- DB HELPERS ----------------
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db_conn()
    cur = conn.cursor()

    # users master
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            account TEXT PRIMARY KEY,
            phone TEXT NOT NULL,
            name TEXT NOT NULL,
            balance INTEGER NOT NULL,
            blocked INTEGER NOT NULL DEFAULT 0
        )
    """)

    # transactions history
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT NOT NULL,
            account TEXT NOT NULL,
            phone TEXT NOT NULL,
            amount INTEGER NOT NULL,
            location TEXT NOT NULL,
            device TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def get_user_by_account_phone(account: str, phone: str):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE account=? AND phone=?", (account, phone))
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_account(account: str):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE account=?", (account,))
    row = cur.fetchone()
    conn.close()
    return row


def update_user_balance(account: str, new_balance: int):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET balance=? WHERE account=?", (new_balance, account))
    conn.commit()
    conn.close()


def set_user_block(account: str, blocked: int):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET blocked=? WHERE account=?", (blocked, account))
    conn.commit()
    conn.close()


# ---------------- OTP + LOCK (3 tries => 30 sec lock) ----------------
def generate_otp():
    return str(random.randint(100000, 999999))


def is_locked(prefix: str) -> int:
    lock_until = int(session.get(f"{prefix}_lock_until", 0) or 0)
    now = int(time.time())
    if now < lock_until:
        return lock_until - now
    return 0


def fail_attempt(prefix: str) -> int:
    tries = int(session.get(f"{prefix}_tries", 0) or 0) + 1
    session[f"{prefix}_tries"] = tries
    if tries >= 3:
        session[f"{prefix}_lock_until"] = int(time.time()) + 30
        session[f"{prefix}_tries"] = 0
        return 30
    return 0


def reset_attempts(prefix: str):
    session[f"{prefix}_tries"] = 0
    session[f"{prefix}_lock_until"] = 0


# ---------------- FRAUD LOGIC ----------------
def detect_fraud(amount: int) -> str:
    # Simple rule based
    return "FRAUD" if amount >= 50000 else "SAFE"


# ---------------- ADMIN GATE (Only you) ----------------
@app.route("/admin-gate/<key>")
def admin_gate(key):
    if key == ADMIN_GATE_KEY:
        session["admin_gate"] = True
        return redirect(url_for("index", tab="admin", msg="Admin gate unlocked ✅"))
    return "Access Denied", 403


def require_admin_gate():
    return True


# ---------------- HOME ----------------
@app.route("/", methods=["GET"])
def index():
    tab = request.args.get("tab", "user")
    msg = request.args.get("msg", "")
    # NOTE: index.html should include lock_msg optionally
    lock_msg = request.args.get("lock_msg", "")
    return render_template("index.html", tab=tab, msg=msg, lock_msg=lock_msg)


# ---------------- USER: SEND OTP ----------------
@app.route("/user/send-otp", methods=["POST"])
def user_send_otp():
    left = is_locked("user")
    if left:
        return render_template("index.html", tab="user",
                               msg="Too many attempts.",
                               lock_msg=f"Try again after {left} sec.")

    account = (request.form.get("account") or "").strip()
    phone = (request.form.get("phone") or "").strip()

    if not account or not phone:
        return redirect(url_for("index", tab="user", msg="Enter account number and phone number"))

    user = get_user_by_account_phone(account, phone)
    if not user:
        return redirect(url_for("index", tab="user", msg="User not found. Admin upload users CSV first."))

    if int(user["blocked"]) == 1:
        return redirect(url_for("index", tab="user", msg="Account BLOCKED by Admin."))

    otp = generate_otp()
    session["user_account"] = account
    session["user_phone"] = phone
    session["user_verified"] = False
    session["user_otp"] = otp

    return render_template("index.html",
                           tab="user",
                           msg="OTP generated. Verify to continue.",
                           show_user_otp=True,
                           otp=otp,
                           account=account,
                           phone=phone)


# ---------------- USER: VERIFY OTP ----------------
@app.route("/user/verify-otp", methods=["POST"])
def user_verify_otp():
    real = session.get("user_otp")
    if not real:
        return redirect(url_for("index", tab="user", msg="Session expired. Try again."))

    left = is_locked("user")
    if left:
        return render_template("index.html",
                               tab="user",
                               msg="Locked temporarily.",
                               lock_msg=f"Try again after {left} sec.",
                               show_user_otp=True,
                               otp=real,
                               account=session.get("user_account", ""),
                               phone=session.get("user_phone", ""))

    entered = (request.form.get("otp") or "").strip()
    if entered != real:
        wait = fail_attempt("user")
        lock_msg = f"Try again after {wait} sec." if wait else "Wrong OTP. Try again."
        return render_template("index.html",
                               tab="user",
                               msg="Invalid OTP.",
                               lock_msg=lock_msg,
                               show_user_otp=True,
                               otp=real,
                               account=session.get("user_account", ""),
                               phone=session.get("user_phone", ""))

    reset_attempts("user")
    session["user_verified"] = True
    return redirect(url_for("user_dashboard"))


# ---------------- USER DASHBOARD ----------------
@app.route("/user/dashboard", methods=["GET"])
def user_dashboard():
    if not session.get("user_verified"):
        return redirect(url_for("index", tab="user", msg="Please login and verify OTP first."))

    account = session.get("user_account")
    phone = session.get("user_phone")

    user = get_user_by_account(account)
    if not user:
        session.clear()
        return redirect(url_for("index", tab="user", msg="User missing. Admin upload users again."))

    if int(user["blocked"]) == 1:
        session.clear()
        return redirect(url_for("index", tab="user", msg="Account BLOCKED by Admin."))

    masked = "XXXXXX" + account[-4:] if account and len(account) > 4 else "XXXX"
    return render_template("user_dashboard.html",
                           name=user["name"],
                           masked=masked,
                           phone=phone,
                           balance=int(user["balance"]))


# ---------------- USER: AMOUNT PAGE (GET/POST) ----------------
@app.route("/user/amount", methods=["GET", "POST"])
def user_amount():
    if not session.get("user_verified"):
        return redirect(url_for("index", tab="user", msg="Please login and verify OTP first."))

    account = session.get("user_account")
    phone = session.get("user_phone")

    user = get_user_by_account(account)
    if not user:
        session.clear()
        return redirect(url_for("index", tab="user", msg="User missing. Admin upload users again."))

    if int(user["blocked"]) == 1:
        session.clear()
        return redirect(url_for("index", tab="user", msg="Account BLOCKED by Admin."))

    name = user["name"]
    balance = int(user["balance"])

    if request.method == "GET":
        return render_template("user_amount.html", name=name, balance=balance)

    amount_str = (request.form.get("amount") or "").strip()
    try:
        amount = int(amount_str)
    except:
        return render_template("user_amount.html", name=name, balance=balance, msg="Enter valid amount.")

    if amount <= 0:
        return render_template("user_amount.html", name=name, balance=balance, msg="Amount must be > 0.")

    if amount > balance:
        return render_template("user_amount.html", name=name, balance=balance, msg="Insufficient balance.")

    status = detect_fraud(amount)
    device = (request.headers.get("User-Agent") or "Unknown")[:120]
    location = "India"
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save transaction
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO transactions (time, account, phone, amount, location, device, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (time_str, account, phone, amount, location, device, status))
    conn.commit()
    conn.close()

    # Update balance if SAFE
    if status == "SAFE":
        new_balance = balance - amount
        update_user_balance(account, new_balance)
        balance = new_balance

    return render_template("user_amount.html",
                           name=name,
                           balance=balance,
                           result=status,
                           amount=amount)


# ---------------- REGISTER (NEW USER) ----------------
@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")


@app.route("/register-user", methods=["POST"])
def register_user():
    name = (request.form.get("name") or "").strip()
    account = (request.form.get("account") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    bal_str = (request.form.get("balance") or "").strip()

    if not name or not account or not phone or not bal_str:
        return redirect(url_for("register_page", msg="Fill all fields"))

    try:
        balance = int(float(bal_str))
    except:
        return redirect(url_for("register_page", msg="Invalid balance"))

    # Insert into DB
    try:
        conn = db_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (account, phone, name, balance, blocked)
            VALUES (?, ?, ?, ?, 0)
        """, (account, phone, name, balance))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return redirect(url_for("register_page", msg="Account already exists"))

    # Append to CSV (best-effort)
    try:
        file_exists = os.path.isfile(CSV_USERS_PATH)
        with open(CSV_USERS_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["account", "phone", "name", "balance"])
            writer.writerow([account, phone, name, balance])
    except:
        pass

    return redirect(url_for("index", tab="user", msg="New user registered ✅ Now login."))


# ---------------- LOGOUT ----------------
@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("index", tab="user", msg="Logged out."))


# ---------------- ADMIN: SEND OTP ----------------
@app.route("/admin/send-otp", methods=["POST"])
def admin_send_otp():
    if not require_admin_gate():
        return "Access Denied", 403

    left = is_locked("admin")
    if left:
        return render_template("index.html", tab="admin",
                               msg="Too many attempts.",
                               lock_msg=f"Try again after {left} sec.")

    admin_id = (request.form.get("admin_id") or "").strip()
    password = (request.form.get("password") or "").strip()

    if admin_id != ADMIN_ID or password != ADMIN_PASS:
        return redirect(url_for("index", tab="admin", msg="Wrong Admin ID or Password"))

    otp = generate_otp()
    session["admin_otp"] = otp
    session["admin_verified"] = False

    return render_template("index.html", tab="admin",
                           msg="Admin OTP generated. Verify to open dashboard.",
                           show_admin_otp=True, otp=otp)


# ---------------- ADMIN: VERIFY OTP ----------------
@app.route("/admin/verify-otp", methods=["POST"])
def admin_verify_otp():
    if not require_admin_gate():
        return "Access Denied", 403

    real = session.get("admin_otp")
    if not real:
        return redirect(url_for("index", tab="admin", msg="Session expired. Try again."))

    left = is_locked("admin")
    if left:
        return render_template("index.html", tab="admin",
                               msg="Locked temporarily.",
                               lock_msg=f"Try again after {left} sec.",
                               show_admin_otp=True, otp=real)

    entered = (request.form.get("otp") or "").strip()
    if entered != real:
        wait = fail_attempt("admin")
        lock_msg = f"Try again after {wait} sec." if wait else "Wrong OTP. Try again."
        return render_template("index.html", tab="admin",
                               msg="Invalid OTP.",
                               lock_msg=lock_msg,
                               show_admin_otp=True, otp=real)

    reset_attempts("admin")
    session["admin_verified"] = True
    return redirect(url_for("admin_dashboard"))


# ---------------- ADMIN: FILTERS + KPIs ----------------
def build_admin_filters():
    q = (request.args.get("q", "") or "").strip()
    status = (request.args.get("status", "ALL") or "ALL").strip().upper()

    where = []
    params = []

    if q:
        where.append("(account LIKE ? OR phone LIKE ? OR device LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])

    if status in ("SAFE", "FRAUD"):
        where.append("status = ?")
        params.append(status)
    else:
        status = "ALL"

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    return q, status, where_sql, params


def get_kpis(conn):
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM transactions")
    total = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM transactions WHERE status='SAFE'")
    safe = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM transactions WHERE status='FRAUD'")
    fraud = cur.fetchone()["c"]

    rate = (fraud / total * 100.0) if total else 0.0
    return {"total": total, "safe": safe, "fraud": fraud, "fraud_rate": rate}


# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    if not require_admin_gate():
        return "Access Denied", 403

    if not session.get("admin_verified"):
        return redirect(url_for("index", tab="admin", msg="Admin verification required."))

    msg = request.args.get("msg", "")

    q, status, where_sql, params = build_admin_filters()

    conn = db_conn()
    cur = conn.cursor()

    kpis = get_kpis(conn)

    cur.execute(f"SELECT * FROM transactions{where_sql} ORDER BY id DESC", params)
    transactions = cur.fetchall()

    cur.execute("SELECT COUNT(*) AS c FROM users")
    user_count = cur.fetchone()["c"]

    cur.execute("SELECT account, name, phone, balance, blocked FROM users ORDER BY account")
    users = cur.fetchall()

    conn.close()

    return render_template("admin_dashboard.html",
                           msg=msg,
                           transactions=transactions,
                           q=q,
                           status=status,
                           kpis=kpis,
                           user_count=user_count,
                           users=users)


# ---------------- ADMIN: UPLOAD USERS CSV (append/update OR replace all) ----------------
@app.route("/admin/upload-users", methods=["POST"])
def admin_upload_users():
    if not require_admin_gate():
        return "Access Denied", 403
    if not session.get("admin_verified"):
        return redirect(url_for("index", tab="admin", msg="Admin verification required."))

    file = request.files.get("file")
    if not file or file.filename.strip() == "":
        return redirect(url_for("admin_dashboard", msg="Please choose a CSV file."))

    replace_all = (request.form.get("replace_all") == "1")

    try:
        stream = TextIOWrapper(file.stream, encoding="utf-8", newline="")
        reader = csv.DictReader(stream)

        required = {"account", "phone", "name", "balance"}
        headers = set([h.strip() for h in (reader.fieldnames or [])])
        if not required.issubset(headers):
            return redirect(url_for("admin_dashboard", msg="CSV headers must be: account, phone, name, balance"))

        conn = db_conn()
        cur = conn.cursor()

        if replace_all:
            cur.execute("DELETE FROM users")

        count = 0
        for row in reader:
            account = (row.get("account") or "").strip()
            phone = (row.get("phone") or "").strip()
            name = (row.get("name") or "").strip()
            bal = (row.get("balance") or "").strip()

            if not account or not phone or not name or not bal:
                continue

            try:
                bal_int = int(float(bal))
            except:
                continue

            # upsert keep blocked if exists
            cur.execute("""
                INSERT INTO users (account, phone, name, balance, blocked)
                VALUES (?, ?, ?, ?, COALESCE((SELECT blocked FROM users WHERE account=?), 0))
                ON CONFLICT(account) DO UPDATE SET
                    phone=excluded.phone,
                    name=excluded.name,
                    balance=excluded.balance
            """, (account, phone, name, bal_int, account))

            count += 1

        conn.commit()
        conn.close()

        msg = f"Users uploaded: {count}"
        if replace_all:
            msg += " (Replaced All)"
        return redirect(url_for("admin_dashboard", msg=msg))

    except Exception:
        return redirect(url_for("admin_dashboard", msg="Upload failed. Save CSV as UTF-8 and try again."))


# ---------------- ADMIN: BLOCK / UNBLOCK ----------------
@app.route("/admin/block", methods=["POST"])
def admin_block():
    if not require_admin_gate():
        return "Access Denied", 403
    if not session.get("admin_verified"):
        return redirect(url_for("index", tab="admin", msg="Admin verification required."))

    account = (request.form.get("account") or "").strip()
    if account:
        set_user_block(account, 1)
    return redirect(url_for("admin_dashboard", msg="Account blocked."))


@app.route("/admin/unblock", methods=["POST"])
def admin_unblock():
    if not require_admin_gate():
        return "Access Denied", 403
    if not session.get("admin_verified"):
        return redirect(url_for("index", tab="admin", msg="Admin verification required."))

    account = (request.form.get("account") or "").strip()
    if account:
        set_user_block(account, 0)
    return redirect(url_for("admin_dashboard", msg="Account unblocked."))


# ---------------- ADMIN: EXPORT CSV ----------------
@app.route("/admin/export.csv", methods=["GET"])
def admin_export_csv():
    if not require_admin_gate():
        return "Access Denied", 403
    if not session.get("admin_verified"):
        return redirect(url_for("index", tab="admin", msg="Admin verification required."))

    q, status, where_sql, params = build_admin_filters()

    conn = db_conn()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM transactions{where_sql} ORDER BY id DESC", params)
    rows = cur.fetchall()
    conn.close()

    def generate():
        header = ["Time", "Account", "Phone", "Amount", "Location", "Device", "Status"]
        yield ",".join(header) + "\n"
        for r in rows:
            line = [
                r["time"],
                r["account"],
                r["phone"],
                str(r["amount"]),
                r["location"],
                (r["device"] or "").replace(",", " "),
                r["status"]
            ]
            yield ",".join(line) + "\n"

    return Response(generate(),
                    mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=transactions_export.csv"})


# ---------------- INIT DB FOR RENDER/GUNICORN ----------------
# This runs when gunicorn imports app:app (safe, not recursive)
try:
    init_db()
except Exception:
    pass


# ---------------- LOCAL RUN ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)