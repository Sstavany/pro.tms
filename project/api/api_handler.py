from flask import Flask, request, jsonify
from flask_cors import CORS
import json, os, time, datetime, requests

app = Flask(__name__)
CORS(app)

DATA_FILE = "/tmp/users.json"

def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

@app.route("/api/add", methods=["POST"])
def add_user():
    uid = request.json.get("uid")
    days = request.json.get("days", 0)
    if not uid:
        return jsonify({"error": "UID required"}), 400
    users = load_users()
    expire = time.time() + days * 86400
    users[uid] = expire
    save_users(users)
    return jsonify({"message": "Added", "uid": uid, "expire": expire})

@app.route("/api/remove", methods=["POST"])
def remove_user():
    uid = request.json.get("uid")
    users = load_users()
    if uid in users:
        del users[uid]
        save_users(users)
        return jsonify({"message": "Removed"})
    return jsonify({"error": "Not found"}), 404

@app.route("/api/list", methods=["GET"])
def list_users():
    users = load_users()
    now = time.time()
    result = [
        {"uid": uid, "expire": datetime.datetime.fromtimestamp(exp).isoformat()}
        for uid, exp in users.items()
        if exp > now
    ]
    return jsonify(result)

@app.route("/api/cron/check", methods=["GET"])
def cron_check():
    users = load_users()
    now = time.time()
    new_users = {uid: exp for uid, exp in users.items() if exp > now}
    save_users(new_users)
    return jsonify({"message": "Cleaned expired users"})

if __name__ == "__main__":
    app.run()
