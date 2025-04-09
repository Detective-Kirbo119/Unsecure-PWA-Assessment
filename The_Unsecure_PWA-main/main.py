from flask import Flask, render_template, request, redirect, session, url_for, abort
import user_management as dbHandler
import pyotp
import qrcode
import base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from io import BytesIO
import re
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a secure random secret key
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Global limits (optional)
)


def is_safe_url(target):
    """Validate if the URL is safe for redirection. Input validation of url"""
    host_url = request.host_url
    return target.startswith(host_url)

@app.route("/success.html", methods=["POST", "GET"])
def addFeedback():
    if request.method == "GET":
        target_url = request.args.get("url")
        if target_url and is_safe_url(target_url):
            return redirect(target_url, code=302)

    if request.method == "POST":
        feedback = request.form.get("feedback")
        if feedback:
            dbHandler.insertFeedback(feedback)
        feedbacks = dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back", feedbacks=feedbacks)
    
    feedbacks = dbHandler.listFeedback()
    return render_template("/success.html", state=True, value="Back", feedbacks=feedbacks)

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET":
        target_url = request.args.get("url")
        if target_url and is_safe_url(target_url):
            return redirect(target_url, code=302)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        dob = request.form.get("dob")
        if username and password and dob:
            # Validate input
            if not re.match(r"^[a-zA-Z0-9_]+$", username):
                return render_template("/signup.html", error="Invalid username format.")
            if len(password) < 8:
                return render_template("/signup.html", error="Password must be at least 8 characters long.")
            dbHandler.insertUser(username, password, dob)
            return redirect(url_for("home"))
    
    return render_template("/signup.html")

@app.route("/get_2fa", methods=["POST", "GET"])
def get_2fa():
    secret = session.get("2fa_secret")
    username = session.get("username")
    print(f"Session username: {session.get('username')}")
    print(f"Session 2FA secret: {session.get('2fa_secret')}")
    if not secret or not username:
        print("[/get_2fa] Missing session variables")
        return redirect(url_for("home"))

    try:
        totp = pyotp.TOTP(secret)
        qr_code_data = totp.provisioning_uri(username, issuer_name="Skibidi")
        qr = qrcode.make(qr_code_data)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode("utf-8")
        print(f"Generated QR code for username: {username}")
    except Exception as e:
        print(f"[get_2fa Error]: {e}")
        abort(500)
    return render_template("get_2fa.html", qr_code=qr_code)

@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
@limiter.limit("2 per minute", methods=["POST"])  # Limits the login attempts to # per minute per IP
def home():
    if request.method == "GET":
        target_url = request.args.get("url")
        if target_url and is_safe_url(target_url):
            return redirect(target_url, code=302)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate input
        if not username or not password:
            return render_template("/index.html", error="Username and password are required.")

        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            return render_template("/index.html", error="Invalid username format.")

        try:
            if dbHandler.retrieveUsers(username, password):
                print(f"Login successful for username: {username}")
                session["username"] = username
                session["2fa_secret"] = pyotp.random_base32()
                return redirect(url_for("get_2fa"))
            else:
                print(f"Login failed for username: {username}")
                return render_template("/index.html", error="Invalid username or password.")
        except Exception as e:
            print(f"[Login Error]: {e}")
            return render_template("/index.html", error="An error occurred. Please try again later.")

    return render_template("/index.html")

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
