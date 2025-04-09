from flask import Flask, render_template, request, redirect, session, flash
import json
import os
from Crypto.Cipher import AES
import base64

# AES must use 16, 24, or 32 byte key
AES_KEY = b'ThisIsASecretKey'  # keep this same in vpn_gui.py too!

def pad(text):
    return text + (16 - len(text) % 16) * ' '

def encrypt_password(password):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = pad(password).encode()
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()

def decrypt_password(encrypted_password):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decoded = base64.b64decode(encrypted_password)
    decrypted = cipher.decrypt(decoded).decode().rstrip()
    return decrypted
app = Flask(__name__)

# Load secret key for Flask session
with open("secret_key.txt", "r") as f:
    app.secret_key = f.read()

# Load users from JSON
def load_users():
    with open("users.json", "r") as f:
        return json.load(f)

# Save users to JSON
def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

# === Routes ===

@app.route("/")
def home():
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        users = load_users()
        username = request.form["username"]
        password = request.form["password"]
        if username in users and decrypt_password(users[username]["password"]) == password:
            session["username"] = username
            return redirect("/dashboard")
        else:
            flash("Invalid credentials!")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    return f"<h2>Welcome, {session['username']}!</h2><br><a href='/logout'>Logout</a>"

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/login")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        admin_pass = request.form["adminpass"]
        if admin_pass == "admin123":  # or load from env later
            session["is_admin"] = True
            return redirect("/adminpanel")
        else:
            flash("Wrong admin password!")
    return render_template("admin.html")

@app.route("/adminpanel", methods=["GET", "POST"])
def adminpanel():
    if not session.get("is_admin"):
        return redirect("/admin")

    users = load_users()

    if request.method == "POST":
        new_user = request.form["newuser"]
        new_pass = request.form["newpass"]
        if new_user in users:
            flash("User already exists!")
        else:
            users[new_user] = {
                "password": encrypt_password(new_pass),
                "role": "user"
            }
            save_users(users)
            flash("User registered successfully!")
    
    return render_template("admin.html", users=users)
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
                return {"status": "success"}, 200

        return {"status": "error", "message": "Invalid credentials"}, 401

    except Exception as e:
        return {"status": "error", "message": f"Server error: {str(e)}"}, 500

if __name__ == "__main__":
    app.run(debug=True)
