from flask import Flask, redirect
import os

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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)