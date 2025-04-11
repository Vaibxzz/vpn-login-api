from flask import Flask, request, render_template, redirect, session, jsonify
from Crypto.Cipher import AES
import base64, json, os, requests
from datetime import datetime

app = Flask(__name__)
app.secret_key = "super_secret_key"

AES_KEY = b'ThisIsASecretKey'
USERS_FILE = "users.json"
LOG_FILE = "vpn_logs.csv"

# === Padding helpers ===
def pad(msg):
    return msg + (16 - len(msg) % 16) * ' '

# === AES password functions ===
def encrypt_password(pwd):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(pwd).encode())).decode()

def decrypt_password(enc_pwd):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(enc_pwd)).decode().rstrip()
    return decrypted

# === Load/save user data ===
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=4)

# === Logging uploads ===
def log_upload(username, ip, location):
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("Time,Username,IP,Location\n")
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()},{username},{ip},{location}\n")

# === Login Route ===
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        users = load_users()

        if username in users:
            user = users[username]
            if user.get("approved") and decrypt_password(user["password"]) == password:
                session["username"] = username
                if username == "admin":
                    return redirect("/admin")
                return redirect("/dashboard")
            else:
                return render_template("login.html", error="Not approved or wrong password")
        return render_template("login.html", error="User not found")
    return render_template("login.html")

# === Logout ===
@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/login")

# === Dashboard (User) ===
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    return render_template("dashboard.html", username=session["username"])

# === Admin Panel ===
@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if "username" not in session or session["username"] != "admin":
        return redirect("/login")

    users = load_users()

    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username")

        if action == "approve":
            if username in users:
                users[username]["approved"] = True
                save_users(users)
        elif action == "remove":
            if username in users:
                users.pop(username)
                save_users(users)
        elif action == "add":
            new_username = request.form.get("new_username")
            new_password = request.form.get("new_password")
            if new_username and new_password:
                users[new_username] = {
                    "password": encrypt_password(new_password),
                    "approved": False
                }
                save_users(users)

    return render_template("admin.html", users=users)

# === API Login for vpn_gui.py ===
@app.route("/api/login", methods=["POST"])
def api_login():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")
        users = load_users()

        if username in users:
            stored_password = users[username]["password"]
            if decrypt_password(stored_password) == password:
                # Get IP + location
                client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
                try:
                    lookup = requests.get(f"http://ip-api.com/json/{client_ip}", timeout=5).json()
                    location = f"{lookup.get('city', 'Unknown')}, {lookup.get('countryCode', '')}"
                except:
                    location = "Unknown"

                return {
                    "status": "success",
                    "ip": client_ip,
                    "location": location
                }, 200

        return {"status": "error", "message": "Invalid credentials"}, 401

    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}, 500

if __name__ == "__main__":
    app.run(debug=True)
