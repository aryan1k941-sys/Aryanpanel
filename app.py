import os, json, hmac, hashlib, secrets, sqlite3, time
from decimal import Decimal, InvalidOperation
from functools import wraps
from urllib.parse import urlparse
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "CHANGE-ME-before-deploy-" + secrets.token_hex(16))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
DB_PATH = os.environ.get("DATABASE_PATH", "reseller.db")
FAM_BASE = "https://famgateway.in"

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', balance REAL NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS services(
          id INTEGER PRIMARY KEY AUTOINCREMENT, provider_service_id TEXT NOT NULL,
          name TEXT NOT NULL, description TEXT DEFAULT '', provider_cost REAL NOT NULL DEFAULT 0,
          price REAL NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS orders(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, service_id INTEGER NOT NULL,
          target TEXT NOT NULL, quantity INTEGER NOT NULL, price REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          provider_order_id TEXT, provider_response TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(service_id) REFERENCES services(id)
        );
        CREATE TABLE IF NOT EXISTS payments(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount REAL NOT NULL,
          gateway_order_id TEXT UNIQUE, status TEXT NOT NULL DEFAULT 'pending', utr TEXT,
          checkout_url TEXT, qr_url TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          credited_at TEXT, FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS ledger(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount REAL NOT NULL,
          kind TEXT NOT NULL, reference TEXT, note TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        # Admin is provisioned only from environment variables, never from public signup.
        admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if admin_email and admin_password and not c.execute("SELECT id FROM users WHERE email=?", (admin_email,)).fetchone():
            from werkzeug.security import generate_password_hash
            c.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')",
                      ("Administrator", admin_email, generate_password_hash(admin_password)))
        c.commit()

def setting(key, default=""):
    with db() as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def save_setting(key, value):
    with db() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, str(value)))
        c.commit()

def current_user():
    uid = session.get("uid")
    if not uid: return None
    with db() as c:
        row = c.execute("SELECT id,name,email,role,balance FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None

@app.context_processor
def inject_user():
    return {"me": current_user(), "site_name": setting("site_name", "ARYAN RESELLER")}

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not current_user():
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        u = current_user()
        if not u or u["role"] != "admin":
            abort(403)
        return fn(*a, **kw)
    return wrapped

def money(v):
    try:
        x = Decimal(str(v))
        if not x.is_finite() or x <= 0: raise ValueError
        return float(x.quantize(Decimal("0.01")))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Enter a valid amount greater than zero.")

def safe_provider_url(raw):
    p = urlparse(raw or "")
    if p.scheme != "https" or not p.netloc:
        raise ValueError("Provider API URL must be a valid HTTPS URL.")
    return raw.rstrip("/")

def provider_request(path, payload=None, method="POST"):
    base = safe_provider_url(setting("provider_api_url"))
    key = setting("provider_api_key")
    if not key:
        raise RuntimeError("Provider API key is not configured in Admin → API Settings.")
    # Generic adapter: default convention is X-Api-Key + JSON. Adjust path/field names to the provider docs.
    endpoint = base + "/" + path.lstrip("/")
    headers = {"X-Api-Key": key, "Authorization": f"Bearer {key}", "Accept": "application/json"}
    resp = requests.request(method, endpoint, headers=headers, json=payload, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, (dict, list)):
        raise RuntimeError("Provider returned an unexpected response.")
    return data

@app.get("/")
def home():
    with db() as c:
        services = c.execute("SELECT * FROM services WHERE active=1 ORDER BY id DESC LIMIT 12").fetchall()
    return render_template("home.html", services=services)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()[:80]
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not name or "@" not in email or len(password) < 8:
            flash("Name, valid email, and password of at least 8 characters are required.", "error")
        else:
            from werkzeug.security import generate_password_hash
            try:
                with db() as c:
                    c.execute("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)",
                              (name,email,generate_password_hash(password)))
                    c.commit()
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "error")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        from werkzeug.security import check_password_hash
        with db() as c:
            row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["uid"] = row["id"]
            return redirect(url_for("admin_dashboard" if row["role"] == "admin" else "dashboard"))
        flash("Incorrect email or password.", "error")
    return render_template("auth.html", mode="login")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.get("/dashboard")
@login_required
def dashboard():
    u = current_user()
    with db() as c:
        orders = c.execute("""SELECT o.*,s.name service_name FROM orders o JOIN services s ON s.id=o.service_id
                              WHERE o.user_id=? ORDER BY o.id DESC LIMIT 30""", (u["id"],)).fetchall()
        payments = c.execute("SELECT * FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 20", (u["id"],)).fetchall()
        services = c.execute("SELECT * FROM services WHERE active=1 ORDER BY name", ()).fetchall()
        ledger = c.execute("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 15", (u["id"],)).fetchall()
    return render_template("dashboard.html", user=u, orders=orders, payments=payments, services=services, ledger=ledger)

@app.post("/order")
@login_required
def create_order():
    u = current_user()
    try:
        service_id = int(request.form.get("service_id","0"))
        quantity = int(request.form.get("quantity","0"))
        target = request.form.get("target","").strip()[:500]
        if quantity < 1 or quantity > 10000000 or not target:
            raise ValueError("Enter a valid target and quantity.")
        with db() as c:
            s = c.execute("SELECT * FROM services WHERE id=? AND active=1", (service_id,)).fetchone()
            if not s: raise ValueError("Service not found.")
            # Price stored per unit; all charge calculations happen server-side.
            total = round(float(s["price"]) * quantity, 2)
            fresh = c.execute("SELECT balance FROM users WHERE id=?", (u["id"],)).fetchone()
            if fresh["balance"] < total: raise ValueError("Insufficient wallet balance. Add funds first.")
            c.execute("UPDATE users SET balance=balance-? WHERE id=?", (total,u["id"]))
            c.execute("INSERT INTO ledger(user_id,amount,kind,note) VALUES(?,?,?,?)",
                      (u["id"],-total,"order",f"Order debit for {s['name']}"))
            cur = c.execute("INSERT INTO orders(user_id,service_id,target,quantity,price,status) VALUES(?,?,?,?,?,'pending')",
                            (u["id"],service_id,target,quantity,total))
            order_id = cur.lastrowid
            c.commit()
        # Generic provider adapter. Exact fields/endpoints need the provider's API documentation.
        try:
            payload = {"service": s["provider_service_id"], "link": target, "quantity": quantity}
            result = provider_request(setting("provider_order_path","api/order"), payload)
            provider_id = str(result.get("order", result.get("order_id", ""))) if isinstance(result,dict) else ""
            with db() as c:
                c.execute("UPDATE orders SET status=?,provider_order_id=?,provider_response=? WHERE id=?",
                          ("submitted" if provider_id or result else "pending", provider_id, json.dumps(result)[:4000], order_id))
                c.commit()
        except Exception as e:
            # Do not silently refund automatically: provider may have accepted request before timing out.
            with db() as c:
                c.execute("UPDATE orders SET status='provider_error',provider_response=? WHERE id=?",
                          (str(e)[:1000],order_id))
                c.commit()
            flash(f"Order saved but provider submission needs admin review: {e}", "error")
            return redirect(url_for("dashboard"))
        flash(f"Order #{order_id} submitted.", "success")
    except (ValueError, TypeError) as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))

@app.post("/wallet/create")
@login_required
def wallet_create():
    u = current_user()
    try:
        amount = money(request.form.get("amount"))
        if amount < float(setting("minimum_topup","10")):
            raise ValueError(f"Minimum top-up is ₹{setting('minimum_topup','10')}.")
        api_key = setting("famgateway_api_key")
        if not api_key: raise ValueError("Admin has not configured FamGateway API Key.")
        redirect_url = url_for("payment_return", _external=True)
        webhook_url = url_for("fam_webhook", _external=True)
        payload = {"amount": amount, "customer_name": u["name"], "customer_email": u["email"],
                   "redirect_url": redirect_url, "webhook_url": webhook_url}
        resp = requests.post(FAM_BASE + "/api/create-order",
             headers={"X-Api-Key": api_key, "Content-Type":"application/json"},
             json=payload, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        info = data.get("data", data)
        gateway_id = info.get("order_id")
        checkout = info.get("checkout_url") or (FAM_BASE + "/pay.php?order_id=" + str(gateway_id) if gateway_id else "")
        qr_url = info.get("qr_url","")
        if not gateway_id or not checkout: raise RuntimeError("FamGateway response did not include an order ID/checkout URL.")
        with db() as c:
            c.execute("INSERT INTO payments(user_id,amount,gateway_order_id,status,checkout_url,qr_url) VALUES(?,?,?,'pending',?,?)",
                      (u["id"], amount, gateway_id, checkout, qr_url))
            c.commit()
        return redirect(checkout)
    except Exception as e:
        flash(f"Could not create payment: {str(e)[:250]}", "error")
        return redirect(url_for("dashboard"))

def credit_payment(gateway_order_id, utr=None):
    with db() as c:
        p = c.execute("SELECT * FROM payments WHERE gateway_order_id=?", (gateway_order_id,)).fetchone()
        if not p or p["status"] == "paid" or p["credited_at"]: return False
        c.execute("UPDATE payments SET status='paid',utr=?,credited_at=CURRENT_TIMESTAMP WHERE id=?",
                  (utr,p["id"]))
        c.execute("UPDATE users SET balance=balance+? WHERE id=?", (p["amount"],p["user_id"]))
        c.execute("INSERT INTO ledger(user_id,amount,kind,reference,note) VALUES(?,?,?,?,?)",
                  (p["user_id"],p["amount"],"topup",gateway_order_id,"FamGateway verified top-up"))
        c.commit()
        return True

@app.post("/api/fam-webhook")
def fam_webhook():
    raw = request.get_data()
    signature = request.headers.get("X-FamGateway-Signature","")
    api_key = setting("famgateway_api_key")
    expected = hmac.new(api_key.encode(), raw, hashlib.sha256).hexdigest() if api_key else ""
    if not signature or not expected or not hmac.compare_digest(signature, expected):
        return jsonify({"error":"invalid signature"}), 401
    try: payload = json.loads(raw.decode("utf-8"))
    except Exception: return jsonify({"error":"invalid JSON"}), 400
    if str(payload.get("status","")).lower() == "success" or payload.get("event") == "payment.success":
        order_id = str(payload.get("order_id",""))
        # Webhook signature plus authoritative server-side verification before crediting.
        try:
            r = requests.get(FAM_BASE + "/api/verify-order.php",
                 headers={"X-Api-Key":api_key},
                 params={"order_id":order_id}, timeout=15)
            r.raise_for_status()
            verified = r.json()
            state = str(verified.get("status","")).lower()
            if state == "success" or verified.get("is_paid") is True:
                credit_payment(order_id, payload.get("utr") or verified.get("utr"))
        except Exception:
            app.logger.exception("FamGateway verification failed for %s", order_id)
            return jsonify({"error":"verification unavailable"}), 503
    return jsonify({"status":"received"})

@app.get("/payment-return")
@login_required
def payment_return():
    # Browser redirect alone is NOT proof of payment. The webhook or explicit verify button credits funds.
    flash("Payment return received. Wallet updates only after server-side verification.", "info")
    return redirect(url_for("dashboard"))

@app.post("/wallet/verify/<int:payment_id>")
@login_required
def verify_payment(payment_id):
    u = current_user()
    api_key = setting("famgateway_api_key")
    with db() as c:
        p = c.execute("SELECT * FROM payments WHERE id=? AND user_id=?", (payment_id,u["id"])).fetchone()
    if not p:
        flash("Payment not found.", "error")
        return redirect(url_for("dashboard"))
    if p["status"] == "paid":
        flash("Payment already credited.", "success")
        return redirect(url_for("dashboard"))
    try:
        r = requests.get(FAM_BASE + "/api/verify-order.php", headers={"X-Api-Key":api_key},
                         params={"order_id":p["gateway_order_id"]}, timeout=15)
        r.raise_for_status()
        data = r.json()
        info = data.get("data", data)
        state = str(info.get("status","")).lower()
        if state == "success" or info.get("is_paid") is True:
            credit_payment(p["gateway_order_id"], info.get("utr"))
            flash("Payment verified; wallet updated.", "success")
        else:
            flash(f"Payment status: {state or 'pending'}. Wallet has not been credited.", "info")
    except Exception as e:
        flash(f"Verification failed: {str(e)[:180]}", "error")
    return redirect(url_for("dashboard"))

@app.get("/admin")
@admin_required
def admin_dashboard():
    with db() as c:
        stats = {
          "users": c.execute("SELECT COUNT(*) n FROM users WHERE role='user'").fetchone()["n"],
          "orders": c.execute("SELECT COUNT(*) n FROM orders").fetchone()["n"],
          "payments": c.execute("SELECT COUNT(*) n FROM payments WHERE status='paid'").fetchone()["n"],
          "revenue": c.execute("SELECT COALESCE(SUM(amount),0) n FROM payments WHERE status='paid'").fetchone()["n"],
        }
        services = c.execute("SELECT * FROM services ORDER BY id DESC").fetchall()
        orders = c.execute("""SELECT o.*,u.email,s.name service_name FROM orders o JOIN users u ON u.id=o.user_id
                              JOIN services s ON s.id=o.service_id ORDER BY o.id DESC LIMIT 50""").fetchall()
        users = c.execute("SELECT id,name,email,role,balance,created_at FROM users ORDER BY id DESC LIMIT 100").fetchall()
        payments = c.execute("""SELECT p.*,u.email FROM payments p JOIN users u ON u.id=p.user_id
                                ORDER BY p.id DESC LIMIT 50""").fetchall()
    return render_template("admin.html", stats=stats, services=services, orders=orders, users=users,
       payments=payments, provider_url=setting("provider_api_url"), provider_key_set=bool(setting("provider_api_key")),
       provider_services_path=setting("provider_services_path","api/services"),
       provider_order_path=setting("provider_order_path","api/order"),
       fam_key_set=bool(setting("famgateway_api_key")), upi_id=setting("upi_id"),
       site_name=setting("site_name","ARYAN RESELLER"), minimum_topup=setting("minimum_topup","10"))

@app.post("/admin/settings")
@admin_required
def admin_settings():
    try:
        provider_url = request.form.get("provider_api_url","").strip()
        if provider_url: safe_provider_url(provider_url)
        save_setting("provider_api_url", provider_url)
        # Empty key means preserve existing secret; admins can replace with a new value.
        for form_key, setting_key in [
            ("provider_api_key","provider_api_key"),("famgateway_api_key","famgateway_api_key"),
            ("upi_id","upi_id"),("site_name","site_name"),("provider_services_path","provider_services_path"),
            ("provider_order_path","provider_order_path"),("minimum_topup","minimum_topup")]:
            val = request.form.get(form_key,"").strip()
            if form_key in ("provider_api_key","famgateway_api_key") and not val: continue
            if form_key == "minimum_topup":
                val = str(money(val))
            save_setting(setting_key,val)
        flash("Settings saved. API keys remain server-side and are never sent to browser pages.", "success")
    except Exception as e:
        flash(f"Settings not saved: {e}", "error")
    return redirect(url_for("admin_dashboard") + "#settings")

@app.post("/admin/service")
@admin_required
def admin_add_service():
    try:
        provider_id = request.form.get("provider_service_id","").strip()[:100]
        name = request.form.get("name","").strip()[:120]
        description = request.form.get("description","").strip()[:500]
        cost = float(request.form.get("provider_cost","0"))
        price = float(request.form.get("price","0"))
        if not provider_id or not name or cost < 0 or price < 0: raise ValueError("Enter valid service details.")
        with db() as c:
            c.execute("INSERT INTO services(provider_service_id,name,description,provider_cost,price) VALUES(?,?,?,?,?)",
                      (provider_id,name,description,cost,price))
            c.commit()
        flash("Service added.", "success")
    except Exception as e: flash(f"Service not added: {e}", "error")
    return redirect(url_for("admin_dashboard") + "#services")

@app.post("/admin/service/<int:sid>/toggle")
@admin_required
def toggle_service(sid):
    with db() as c:
        c.execute("UPDATE services SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (sid,))
        c.commit()
    return redirect(url_for("admin_dashboard") + "#services")

@app.post("/admin/service/<int:sid>/price")
@admin_required
def update_price(sid):
    try:
        price = float(request.form.get("price",""))
        if price < 0: raise ValueError()
        with db() as c:
            c.execute("UPDATE services SET price=? WHERE id=?", (price,sid))
            c.commit()
        flash("Selling price updated.", "success")
    except Exception: flash("Invalid price.", "error")
    return redirect(url_for("admin_dashboard") + "#services")

@app.post("/admin/user/<int:uid>/balance")
@admin_required
def adjust_balance(uid):
    try:
        amount = float(request.form.get("amount",""))
        if not amount or abs(amount) > 1000000: raise ValueError()
        with db() as c:
            user = c.execute("SELECT id FROM users WHERE id=? AND role='user'", (uid,)).fetchone()
            if not user: raise ValueError()
            bal = c.execute("SELECT balance FROM users WHERE id=?", (uid,)).fetchone()["balance"]
            if bal + amount < 0: raise ValueError("Balance cannot become negative.")
            c.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount,uid))
            c.execute("INSERT INTO ledger(user_id,amount,kind,note) VALUES(?,?,?,?)",
                      (uid,amount,"admin_adjustment","Admin balance adjustment"))
            c.commit()
        flash("Balance adjusted.", "success")
    except Exception as e: flash(f"Balance adjustment failed: {e}", "error")
    return redirect(url_for("admin_dashboard") + "#users")

@app.post("/admin/order/<int:oid>/status")
@admin_required
def update_order_status(oid):
    status = request.form.get("status","")
    if status not in {"pending","submitted","processing","completed","cancelled","provider_error"}:
        abort(400)
    with db() as c:
        c.execute("UPDATE orders SET status=? WHERE id=?", (status,oid))
        c.commit()
    return redirect(url_for("admin_dashboard") + "#orders")

@app.post("/admin/provider/test")
@admin_required
def test_provider():
    try:
        data = provider_request(setting("provider_services_path","api/services"), method="GET")
        flash("Provider connection responded successfully. Response shape: " + json.dumps(data)[:250], "success")
    except Exception as e:
        flash(f"Provider test failed: {str(e)[:250]}", "error")
    return redirect(url_for("admin_dashboard") + "#settings")

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Admin access required."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","5000")), debug=False)
