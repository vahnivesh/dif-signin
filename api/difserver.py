from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import uuid
import time
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

# ----------------- CONFIG -----------------

# Your ngrok domain
NGROK_URL = "https://dif-signin.vercel.app"

# Where passkeys are stored
PASSKEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "passkey.json")

# Flask setup
app = Flask(__name__, static_folder="public")
CORS(app)

QR_SESSIONS = {}     # session_id -> {username, mode, status, timestamp}
PASSKEYS = {}        # loaded from file


# ----------------- INTERNAL HELPERS -----------------

def load_passkeys():
    global PASSKEYS
    if not os.path.exists(PASSKEY_FILE):
        PASSKEYS = {"users": {}}
        return
    with open(PASSKEY_FILE, "r") as f:
        try:
            PASSKEYS = json.load(f)
        except:
            PASSKEYS = {"users": {}}


def save_passkeys():
    with open(PASSKEY_FILE, "w") as f:
        json.dump(PASSKEYS, f, indent=2)


load_passkeys()
print("Loaded passkeys:", PASSKEYS)


# ----------------- PASSKEY REGISTER -----------------

@app.route("/passkey/register", methods=["POST"])
def passkey_register():
    data = request.get_json()
    username = data.get("username")
    credential_id = data.get("credential_id")
    public_key = data.get("public_key")

    if not username or not credential_id or not public_key:
        return jsonify({"error": "Missing fields"}), 400

    PASSKEYS["users"][username] = {
        "credential_id": credential_id,
        "public_key": public_key,
        "counter": 0
    }

    save_passkeys()
    print("Registered:", username)
    return jsonify({"success": True})


# ----------------- PASSKEY META -----------------

@app.route("/passkey/meta", methods=["GET"])
def passkey_meta():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400

    user_info = PASSKEYS["users"].get(username)
    if not user_info:
        return jsonify({"error": "No registered passkey"}), 404

    return jsonify({
        "username": username,
        "credential_id": user_info["credential_id"]
    })


# ----------------- PASSKEY VERIFY -----------------

@app.route("/passkey/verify", methods=["POST"])
def passkey_verify():
    data = request.get_json()

    username = data.get("username")
    credential_id = data.get("credential_id")
    auth_data = data.get("authenticator_data") or data.get("auth_data")
    client_data = data.get("client_data")
    signature = data.get("signature")

    user_info = PASSKEYS["users"].get(username)
    if not user_info:
        return jsonify({"error": "No registered passkey"}), 404

    if user_info["credential_id"] != credential_id:
        return jsonify({"error": "Wrong passkey for this user"}), 403

    try:
        auth_bytes = base64.b64decode(auth_data)
        client_bytes = base64.b64decode(client_data)
        sig_bytes = base64.b64decode(signature)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(client_bytes)
        client_hash = digest.finalize()

        signed_bytes = auth_bytes + client_hash

        pub = load_der_public_key(base64.b64decode(user_info["public_key"]))
        pub.verify(sig_bytes, signed_bytes, ec.ECDSA(hashes.SHA256()))

    except Exception as e:
        print("verify error:", e)
        return jsonify({"error": "Signature invalid"}), 403

    return jsonify({"success": True})


# ----------------- QR SESSION HELPERS -----------------

def cleanup_sessions():
    now = time.time()
    for sid, sess in list(QR_SESSIONS.items()):
        if now - sess["timestamp"] > 300:  # 5 min
            del QR_SESSIONS[sid]


# ----------------- QR START (SETUP) -----------------

@app.route("/qr/start", methods=["POST"])
def qr_start():
    cleanup_sessions()

    data = request.get_json()
    username = data.get("username")
    public_fp = data.get("publicFP")

    session_id = str(uuid.uuid4())

    QR_SESSIONS[session_id] = {
        "username": username,
        "publicFP": public_fp,
        "mode": "setup",
        "status": "pending",
        "timestamp": time.time()
    }

    # ---- New correct URL served by Flask through ngrok ----
    mobile_url = (
        f"{NGROK_URL}/public/phone-auth-generate.html"
        f"?session={session_id}&user={username}"
    )

    return jsonify({
        "session_id": session_id,
        "mobile_url": mobile_url
    })


@app.route("/qr/complete-setup", methods=["POST"])
def qr_complete_setup():
    data = request.get_json()
    session_id = data.get("session_id")

    if session_id not in QR_SESSIONS:
        return jsonify({"error": "Invalid session"}), 404

    QR_SESSIONS[session_id]["status"] = "registered"
    return jsonify({"success": True})


# ----------------- QR START (LOGIN) -----------------

@app.route("/qr/start-login", methods=["POST"])
def qr_start_login():
    cleanup_sessions()
    data = request.get_json()

    username = data.get("username")

    if username not in PASSKEYS["users"]:
        return jsonify({"error": "User has no passkey"}), 404

    session_id = str(uuid.uuid4())

    QR_SESSIONS[session_id] = {
        "username": username,
        "mode": "login",
        "status": "pending",
        "timestamp": time.time()
    }

    # ---- Correct login URL for phone ----
    mobile_url = (
        f"{NGROK_URL}/public/phone-auth-login.html"
        f"?session={session_id}&user={username}"
    )

    return jsonify({
        "session_id": session_id,
        "mobile_url": mobile_url
    })


@app.route("/qr/mark-authenticated", methods=["POST"])
def qr_mark_authenticated():
    data = request.get_json()
    session_id = data.get("session_id")
    username = data.get("username")

    if session_id not in QR_SESSIONS:
        return jsonify({"error": "Invalid session"}), 404

    if QR_SESSIONS[session_id]["username"] != username:
        return jsonify({"error": "User mismatch"}), 400

    QR_SESSIONS[session_id]["status"] = "authenticated"
    return jsonify({"success": True})


@app.route("/qr/status/<session_id>", methods=["GET"])
def qr_status(session_id):
    cleanup_sessions()

    if session_id not in QR_SESSIONS:
        return jsonify({"error": "Invalid or expired session"}), 404

    return jsonify(QR_SESSIONS[session_id])


# ----------------- STATIC FILE SERVING -----------------

@app.route('/public/<path:filename>')
def serve_public(filename):
    return send_from_directory("public", filename)


# ----------------- RUN SERVER -----------------

if __name__ == "__main__":
    app.run(port=5000, host="0.0.0.0", debug=True)

