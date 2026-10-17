from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify
)

from models import init_db, get_connection
from security import (
    hash_password, verify_password,
    derive_key_from_master, generate_salt, AESEncryption, PasswordBuilder
)
from observers import EventSubject, WeakPasswordObserver, ExpirationObserver
from proxy import SensitiveField, SensitiveFieldProxy


# Flask Setup

app = Flask(__name__)
app.config["SECRET_KEY"] = "change_this_in_production"
AUTO_LOCK_MINUTES = 5


# SessionManager (Singleton)

class SessionManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def login(self, user_id: int, aes_key: bytes):
        session["user_id"] = user_id
        session["last_activity"] = datetime.utcnow().isoformat()
        session["aes_key"] = aes_key.hex()

    def logout(self):
        session.clear()

    def is_authenticated(self):
        return "user_id" in session

    def get_user_id(self):
        self._check_auto_lock()
        return session.get("user_id")

    def get_aes_key(self):
        self._check_auto_lock()
        key_hex = session.get("aes_key")
        if not key_hex:
            return None
        return bytes.fromhex(key_hex)

    def update_activity(self):
        session["last_activity"] = datetime.utcnow().isoformat()

    def _check_auto_lock(self):
        last = session.get("last_activity")
        if not last:
            return
        last_dt = datetime.fromisoformat(last)
        if datetime.utcnow() - last_dt > timedelta(minutes=AUTO_LOCK_MINUTES):
            self.logout()


session_manager = SessionManager()


# Mediator for UI/Data

class UIMediator:
    def __init__(self):
        self.subject = EventSubject()
        self.subject.add_observer(WeakPasswordObserver())
        self.subject.add_observer(ExpirationObserver())

    def get_encryptor(self) -> AESEncryption:
        key = session_manager.get_aes_key()
        return AESEncryption(key)

    def load_items(self, user_id):
        """
        Load all vault items for a user, decrypt, and prepare both
        masked and full values for the UI (mask/unmask + copy).
        """
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM vault_items WHERE user_id = ? ORDER BY id DESC", (user_id,))
        rows = cur.fetchall()
        conn.close()

        enc = self.get_encryptor()
        items = []

        for row in rows:
            # Decrypt everything
            username = enc.decrypt(row["username_enc"]) if row["username_enc"] else ""
            password = enc.decrypt(row["password_enc"]) if row["password_enc"] else ""
            url = enc.decrypt(row["url_enc"]) if row["url_enc"] else ""

            card_number = enc.decrypt(row["card_number_enc"]) if row["card_number_enc"] else ""
            card_holder = enc.decrypt(row["card_holder_enc"]) if row["card_holder_enc"] else ""
            cvv = enc.decrypt(row["card_cvv_enc"]) if row["card_cvv_enc"] else ""

            identity_number = enc.decrypt(row["identity_number_enc"]) if row["identity_number_enc"] else ""
            identity_type = row["identity_type"] or ""

            note = enc.decrypt(row["note_enc"]) if row["note_enc"] else ""

            # Mask using Proxy for sensitive fields
            username_p = SensitiveFieldProxy(SensitiveField(username))
            password_p = SensitiveFieldProxy(SensitiveField(password))
            card_p = SensitiveFieldProxy(SensitiveField(card_number))
            cvv_p = SensitiveFieldProxy(SensitiveField(cvv))
            identity_p = SensitiveFieldProxy(SensitiveField(identity_number))

            items.append({
                "id": row["id"],
                "item_type": row["item_type"],
                "label": row["label"],

                # Login data
                "username_full": username,
                "username_masked": username_p.get_display_value() if username else "",
                "password_full": password,
                "password_masked": password_p.get_display_value() if password else "",
                "url_full": url,

                # Credit card data
                "card_number_full": card_number,
                "card_number_masked": card_p.get_display_value() if card_number else "",
                "card_holder": card_holder,
                "card_expiry": row["card_expiry"] or "",
                "card_cvv_full": cvv,
                "card_cvv_masked": cvv_p.get_display_value() if cvv else "",

                # Identity
                "identity_type": identity_type,
                "identity_number_full": identity_number,
                "identity_number_masked": identity_p.get_display_value() if identity_number else "",

                # Secure note
                "note_full": note,
                "note_preview": (note[:40] + "…") if note and len(note) > 40 else note,
            })

        return items

    def save_login(self, user_id, form):
        enc = self.get_encryptor()

        username = form.get("username") or ""
        password = form.get("password") or ""
        url = form.get("url") or ""
        label = form.get("label") or ""

        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO vault_items (
                user_id, item_type, label,
                username_enc, password_enc, url_enc
            ) VALUES (?, 'LOGIN', ?, ?, ?, ?)
            """,
            (user_id, label,
             enc.encrypt(username), enc.encrypt(password), enc.encrypt(url))
        )
        conn.commit()
        conn.close()

        return self.subject.notify("password_saved", {"password": password})

    def save_card(self, user_id, form):
        enc = self.get_encryptor()

        label = form.get("label") or ""
        number = form.get("card_number") or ""
        holder = form.get("card_holder") or ""
        expiry = form.get("card_expiry") or ""
        cvv = form.get("card_cvv") or ""

        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO vault_items (
                user_id, item_type, label,
                card_number_enc, card_holder_enc, card_expiry, card_cvv_enc
            ) VALUES (?, 'CREDIT_CARD', ?, ?, ?, ?, ?)
            """,
            (user_id, label,
             enc.encrypt(number), enc.encrypt(holder), expiry, enc.encrypt(cvv))
        )
        conn.commit()
        conn.close()

        return self.subject.notify("credit_card_saved", {"expiry_date": expiry})

    def save_identity(self, user_id, form):
        enc = self.get_encryptor()

        label = form.get("label") or ""
        identity_type = form.get("identity_type") or ""
        identity_number = form.get("identity_number") or ""

        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO vault_items (
                user_id, item_type, label,
                identity_number_enc, identity_type
            ) VALUES (?, 'IDENTITY', ?, ?, ?)
            """,
            (user_id, label,
             enc.encrypt(identity_number), identity_type)
        )
        conn.commit()
        conn.close()

        # identities can also have expirations in future; for simplicity we skip observer here
        return []

    def save_note(self, user_id, form):
        enc = self.get_encryptor()

        label = form.get("label") or ""
        note_text = form.get("note") or ""

        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO vault_items (
                user_id, item_type, label, note_enc
            ) VALUES (?, 'SECURE_NOTE', ?, ?)
            """,
            (user_id, label, enc.encrypt(note_text))
        )
        conn.commit()
        conn.close()

        return []


ui = UIMediator()


# Helper Decorator

def require_login(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session_manager.is_authenticated():
            return redirect(url_for("login"))
        session_manager.update_activity()
        return f(*args, **kwargs)
    return wrapper


# Routes: Auth

@app.route("/")
def index():
    if session_manager.is_authenticated():
        return redirect(url_for("vault"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        q1 = request.form["q1"]
        a1 = request.form["a1"]
        q2 = request.form["q2"]
        a2 = request.form["a2"]
        q3 = request.form["q3"]
        a3 = request.form["a3"]

        salt = generate_salt()

        pw_hash = hash_password(password)
        a1_hash = hash_password(a1)
        a2_hash = hash_password(a2)
        a3_hash = hash_password(a3)

        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO users 
                (email, password_hash, salt, q1, a1_hash, q2, a2_hash, q3, a3_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (email, pw_hash, salt, q1, a1_hash, q2, a2_hash, q3, a3_hash)
            )
            conn.commit()
        except Exception:
            conn.close()
            flash("Account creation failed. Email may already exist.", "danger")
            return render_template("register.html")

        conn.close()
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        conn.close()

        if not row or not verify_password(row["password_hash"], password):
            flash("Invalid email or password.", "danger")
            return render_template("login.html")

        key = derive_key_from_master(password, row["salt"])
        session_manager.login(row["id"], key)

        flash("Logged in successfully!", "success")
        return redirect(url_for("vault"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session_manager.logout()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":

        step = request.form.get("step")

        # STEP 1 — Enter email
        if step == "1":
            email = request.form.get("email")

            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cur.fetchone()
            conn.close()

            if not user:
                flash("No account found with that email.", "danger")
                return render_template("forgot.html", step=1)

            return render_template("forgot.html", step=2, user=user)

        # STEP 2 — Answer questions
        if step == "2":
            email = request.form.get("email")
            a1 = request.form.get("a1")
            a2 = request.form.get("a2")
            a3 = request.form.get("a3")

            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cur.fetchone()
            conn.close()

            if (
                verify_password(user["a1_hash"], a1)
                and verify_password(user["a2_hash"], a2)
                and verify_password(user["a3_hash"], a3)
            ):
                return render_template("forgot.html", step=3, email=email)
            else:
                flash("Incorrect answers to security questions.", "danger")
                return render_template("forgot.html", step=1)

        # STEP 3 — Set new password
        if step == "3":
            email = request.form["email"]
            new_pw = request.form["new_password"]

            salt = generate_salt()
            pw_hash = hash_password(new_pw)

            conn = get_connection()
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE email = ?",
                (pw_hash, salt, email)
            )
            conn.commit()
            conn.close()

            flash("Password reset successfully!", "success")
            return redirect(url_for("login"))

    return render_template("forgot.html", step=1)


# Routes: Vault

@app.route("/vault")
@require_login
def vault():
    items = ui.load_items(session_manager.get_user_id())
    return render_template("vault.html", items=items)


#Add Routes

@app.route("/vault/add/login", methods=["GET", "POST"])
@require_login
def add_login():
    if request.method == "POST":
        warnings = ui.save_login(session_manager.get_user_id(), request.form)
        for w in warnings:
            flash(w, "warning")
        flash("Login saved.", "success")
        return redirect(url_for("vault"))
    return render_template("item_form.html", item_type="LOGIN", mode="add", item=None)


@app.route("/vault/add/card", methods=["GET", "POST"])
@require_login
def add_card():
    if request.method == "POST":
        warnings = ui.save_card(session_manager.get_user_id(), request.form)
        for w in warnings:
            flash(w, "warning")
        flash("Credit card saved.", "success")
        return redirect(url_for("vault"))
    return render_template("item_form.html", item_type="CREDIT_CARD", mode="add", item=None)


@app.route("/vault/add/identity", methods=["GET", "POST"])
@require_login
def add_identity():
    if request.method == "POST":
        ui.save_identity(session_manager.get_user_id(), request.form)
        flash("Identity saved.", "success")
        return redirect(url_for("vault"))
    return render_template("item_form.html", item_type="IDENTITY", mode="add", item=None)


@app.route("/vault/add/note", methods=["GET", "POST"])
@require_login
def add_note():
    if request.method == "POST":
        ui.save_note(session_manager.get_user_id(), request.form)
        flash("Secure note saved.", "success")
        return redirect(url_for("vault"))
    return render_template("item_form.html", item_type="SECURE_NOTE", mode="add", item=None)


#Edit Route

@app.route("/vault/edit/<int:item_id>", methods=["GET", "POST"])
@require_login
def edit_item(item_id):
    user_id = session_manager.get_user_id()

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user_id))
    row = cur.fetchone()
    conn.close()

    if not row:
        flash("Item not found.", "danger")
        return redirect(url_for("vault"))

    enc = ui.get_encryptor()

    item_type = row["item_type"]
    item = {
        "id": row["id"],
        "label": row["label"],
        "item_type": item_type,
        "username": enc.decrypt(row["username_enc"]) if row["username_enc"] else "",
        "password": enc.decrypt(row["password_enc"]) if row["password_enc"] else "",
        "url": enc.decrypt(row["url_enc"]) if row["url_enc"] else "",
        "card_number": enc.decrypt(row["card_number_enc"]) if row["card_number_enc"] else "",
        "card_holder": enc.decrypt(row["card_holder_enc"]) if row["card_holder_enc"] else "",
        "card_expiry": row["card_expiry"] or "",
        "card_cvv": enc.decrypt(row["card_cvv_enc"]) if row["card_cvv_enc"] else "",
        "identity_type": row["identity_type"] or "",
        "identity_number": enc.decrypt(row["identity_number_enc"]) if row["identity_number_enc"] else "",
        "note": enc.decrypt(row["note_enc"]) if row["note_enc"] else "",
    }

    if request.method == "POST":
        conn = get_connection()
        cur = conn.cursor()

        if item_type == "LOGIN":
            label = request.form.get("label") or ""
            username = request.form.get("username") or ""
            password = request.form.get("password") or ""
            url = request.form.get("url") or ""
            cur.execute(
                """
                UPDATE vault_items
                SET label = ?, username_enc = ?, password_enc = ?, url_enc = ?
                WHERE id = ? AND user_id = ?
                """,
                (label, enc.encrypt(username), enc.encrypt(password), enc.encrypt(url), item_id, user_id)
            )

        elif item_type == "CREDIT_CARD":
            label = request.form.get("label") or ""
            number = request.form.get("card_number") or ""
            holder = request.form.get("card_holder") or ""
            expiry = request.form.get("card_expiry") or ""
            cvv = request.form.get("card_cvv") or ""
            cur.execute(
                """
                UPDATE vault_items
                SET label = ?, card_number_enc = ?, card_holder_enc = ?, card_expiry = ?, card_cvv_enc = ?
                WHERE id = ? AND user_id = ?
                """,
                (label, enc.encrypt(number), enc.encrypt(holder), expiry, enc.encrypt(cvv), item_id, user_id)
            )

        elif item_type == "IDENTITY":
            label = request.form.get("label") or ""
            identity_type = request.form.get("identity_type") or ""
            identity_number = request.form.get("identity_number") or ""
            cur.execute(
                """
                UPDATE vault_items
                SET label = ?, identity_type = ?, identity_number_enc = ?
                WHERE id = ? AND user_id = ?
                """,
                (label, identity_type, enc.encrypt(identity_number), item_id, user_id)
            )

        elif item_type == "SECURE_NOTE":
            label = request.form.get("label") or ""
            note_text = request.form.get("note") or ""
            cur.execute(
                """
                UPDATE vault_items
                SET label = ?, note_enc = ?
                WHERE id = ? AND user_id = ?
                """,
                (label, enc.encrypt(note_text), item_id, user_id)
            )

        conn.commit()
        conn.close()

        flash("Item updated.", "success")
        return redirect(url_for("vault"))

    return render_template("item_form.html", item_type=item_type, mode="edit", item=item)


#Delete

@app.route("/vault/delete/<int:item_id>", methods=["POST"])
@require_login
def delete_item(item_id):
    user_id = session_manager.get_user_id()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user_id))
    conn.commit()
    conn.close()

    flash("Item deleted.", "info")
    return redirect(url_for("vault"))


# Password Generator

@app.route("/generate_password", methods=["POST"])
@require_login
def generate_password():
    length = int(request.form.get("length", 16))
    password = PasswordBuilder().set_length(length).build()
    return jsonify({"password": password})


# Run App

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
