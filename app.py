from flask import Flask, redirect, request
import requests

app = Flask(__name__)

@app.route("/")
def home():
    user = None

    try:
        # Call Azure Easy Auth endpoint
        resp = requests.get("http://127.0.0.1:8000/.auth/me")
        data = resp.json()
        if data:
            user = data[0]
    except Exception as e:
        user = f"Error: {str(e)}"

    return f"""
    <h2>OAuth Lab</h2>
    <a href="/login">Login with Microsoft</a><br><br>

    <h3>User Info:</h3>
    <pre>{user}</pre>
    """

@app.route("/login")
def login():
    return redirect("/.auth/login/aad")