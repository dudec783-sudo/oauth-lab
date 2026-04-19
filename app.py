from flask import Flask, redirect

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <h2>OAuth Lab</h2>
    <a href="/login">Login with Microsoft</a>
    """

@app.route("/login")
def login():
    return redirect("/.auth/login/aad")