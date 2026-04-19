from flask import Flask, redirect, request
import requests
import os

app = Flask(__name__)

@app.route("/")
def home():
    user = None

    # Call Azure Easy Auth endpoint
    headers = {"X-ZUMO-AUTH": request.headers.get("X-ZUMO-AUTH", "")}
    
    try:
        resp = requests.get(
            os.environ.get("WEBSITE_AUTH_ME_ENDPOINT", "/.auth/me"),
        )
        data = resp.json()
        if data:
            user = data[0]
    except:
        pass

    return f"""
    <h2>OAuth Lab</h2>
    <a href="/login">Login with Microsoft</a><br><br>

    <h3>User Info:</h3>
    <pre>{user}</pre>
    """

@app.route("/login")
def login():
    return redirect("/.auth/login/aad")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)