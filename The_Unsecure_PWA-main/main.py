from flask import Flask, render_template, request, redirect, url_for
import user_management as dbHandler  # Import the user management module (handles database operations)
import re  # For URL validation
import bcrypt  # For password hashing

from urllib.parse import urlparse



# Initialize the Flask web application
app = Flask(__name__)


ALLOWED_DOMAINS = ["yourdomain.com"]

def is_safe_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc in ALLOWED_DOMAINS

@app.route("/redirect", methods=["GET"])
def safe_redirect():
    url = request.args.get("url", "")
    if is_safe_url(url):
        return redirect(url, code=302)
    return "Invalid URL", 400



# ===================== Route: Feedback Submission =====================
@app.route("/success.html", methods=["POST", "GET"])
def addFeedback():
    # Validate URL before redirecting to prevent Open Redirect attacks
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not re.match(r'^https?:\/\/(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
            return "Invalid URL", 400  # Return an error for invalid URLs
        return redirect(url, code=302)
    
    # If it's a POST request, insert feedback into the database
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
    
    dbHandler.listFeedback()
    return render_template("/success.html", state=True, value="Back")


# ===================== Route: User Signup =====================
@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    # Validate URL before redirecting
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not re.match(r'^https?:\/\/(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
            return "Invalid URL", 400
        return redirect(url, code=302)
    
    # Handle user registration (POST request)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        dob = request.form["dob"]
        
        # Hash password before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        dbHandler.insertUser(username, hashed_password.decode('utf-8'), dob)
        return render_template("/index.html")
    
    return render_template("/signup.html")


# ===================== Route: Home/Login Page =====================
@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Validate URL before redirecting
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not re.match(r'^https?:\/\/(?:[-\w.]|(?:%[\da-fA-F]{2}))+', url):
            return "Invalid URL", 400
        return redirect(url, code=302)
    
    # Handle login (POST request)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        # Retrieve user and check password
        user = dbHandler.retrieveUser(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=True)
        else:
            return render_template("/index.html", error="Invalid credentials")
    
    return render_template("/index.html")


# ===================== Run the Flask Application =====================
if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True  # Enable template auto-reloading for development
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0  # Disable file caching (useful for debugging changes)
    
    # Run Flask app in production mode (Disable debug mode for security)
    app.run(host="0.0.0.0", port=5000)