# app_api.py
from flask import Flask, request, jsonify, abort
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta
import os
import secrets

# ---------- CONFIG ----------

uri = "mongodb+srv://sahebrine_db_user:7XlD1xWNVbFvACFh@cluster0.wemjued.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(
    uri,
    server_api=ServerApi("1"),
    tls=True,
    tlsCAFile=certifi.where()
)
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

COL_NAME = "vurekeys"
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-me-to-secure-token")
KEY_PREFIX = "VURE"

# ---------- INIT ----------
app = Flask(__name__)
client = MongoClient(MONGO_URI, server_api=ServerApi("1"))
db = client["sahebrine_db"]
keys_col = db[COL_NAME]

# ---------- HELPERS ----------
def now_utc():
    return datetime.now(timezone.utc)

def iso(dt: datetime):
    return dt.astimezone(timezone.utc).isoformat()

def parse_iso(s):
    return datetime.fromisoformat(s).astimezone(timezone.utc)

def cleanup_expired():
    """حذف المفاتيح التي انتهت صلاحيتها الآن"""
    cur = now_utc()
    res = keys_col.delete_many({"expires_at": {"$lte": cur.isoformat()}})
    return res.deleted_count

def remaining_string(expires_iso):
    try:
        exp = parse_iso(expires_iso)
    except Exception:
        return "Unknown"
    diff = exp - now_utc()
    if diff.total_seconds() <= 0:
        return "Expired"
    days = diff.days
    hours = diff.seconds // 3600
    minutes = (diff.seconds % 3600) // 60
    if days > 0:
        return f"{days} days"
    if hours > 0:
        return f"{hours} hours"
    return f"{minutes} minutes"

def require_admin():
    token = request.headers.get("X-Admin-Token") or request.args.get("admin_token")
    return token == ADMIN_TOKEN

def generate_key(duration_str):
    """duration_str مثال: '1 month' أو '30 day' أو '60 minute'"""
    amount, unit = duration_str.split()
    amount = int(amount)
    unit = unit.lower()
    if unit.startswith("day"):
        expires = now_utc() + timedelta(days=amount)
    elif unit.startswith("hour"):
        expires = now_utc() + timedelta(hours=amount)
    elif unit.startswith("minute"):
        expires = now_utc() + timedelta(minutes=amount)
    elif unit.startswith("week"):
        expires = now_utc() + timedelta(weeks=amount)
    elif unit.startswith("month"):
        expires = now_utc() + relativedelta(months=amount)
    else:
        raise ValueError("Invalid duration unit")
    suffix = secrets.token_hex(3).upper()
    key = f"{KEY_PREFIX}-{amount}{unit[0].upper()}-{suffix}"
    return key, iso(expires)

# ---------- API ROUTES ----------

@app.route("/api/add_key", methods=["POST"])
def api_add_key():
    if not require_admin():
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    cleanup_expired()
    data = request.get_json(force=True)
    name = data.get("name", "default")
    duration = data.get("duration", "1 month")  # default 1 month
    try:
        key, expires_iso = generate_key(duration)
    except Exception as e:
        return jsonify({"ok": False, "msg": "Invalid duration format"}), 400

    doc = {
        "key": key,
        "name": name,
        "expires_at": expires_iso,
        "hwid": None,
        "used": False,
        "created_at": iso(now_utc())
    }
    keys_col.insert_one(doc)
    return jsonify({"ok": True, "key": key, "expires_at": expires_iso}), 201

@app.route("/api/delete_key", methods=["POST"])
def api_delete_key():
    if not require_admin():
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    cleanup_expired()
    data = request.get_json(force=True)
    key = data.get("key")
    if not key:
        return jsonify({"ok": False, "msg": "Missing key"}), 400
    res = keys_col.delete_one({"key": key})
    if res.deleted_count == 0:
        return jsonify({"ok": False, "msg": "Key not found"}), 404
    return jsonify({"ok": True, "msg": "Deleted"}), 200

@app.route("/api/list_key", methods=["GET"])
def api_list_key():
    if not require_admin():
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    cleanup_expired()
    docs = list(keys_col.find({}, {"_id":0}).sort("created_at", -1))
    # Normalize remaining time & status
    out = []
    for d in docs:
        rem = remaining_string(d["expires_at"])
        status = "Active" if rem != "Expired" else "Expired"
        used = True if d.get("used") else False
        out.append({
            "key": d["key"],
            "name": d.get("name"),
            "expires_at": d["expires_at"],
            "remaining": rem,
            "status": status,
            "used": used,
            "hwid": d.get("hwid")
        })
    return jsonify({"ok": True, "keys": out}), 200

@app.route("/api/reset_key", methods=["POST"])
def api_reset_key():
    if not require_admin():
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    cleanup_expired()
    data = request.get_json(force=True)
    key = data.get("key")
    if not key:
        return jsonify({"ok": False, "msg": "Missing key"}), 400
    res = keys_col.update_one({"key": key}, {"$set": {"hwid": None, "used": False}})
    if res.matched_count == 0:
        return jsonify({"ok": False, "msg": "Key not found"}), 404
    return jsonify({"ok": True, "msg": "Reset successful"}), 200

@app.route("/api/check_key", methods=["POST"])
def api_check_key():
    cleanup_expired()
    data = request.get_json(force=True)
    key = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()
    name = data.get("name", "").strip()
    if not key or not hwid:
        return jsonify({"ok": False, "msg": "Missing key or hwid"}), 400

    doc = keys_col.find_one({"key": key})
    if not doc:
        return jsonify({"ok": False, "msg": "invalid key"}, 404)

    # check expiry (in case someone added expiry in past between cleanup)
    exp = parse_iso(doc["expires_at"])
    if now_utc() > exp:
        # delete immediately as requested
        keys_col.delete_one({"key": key})
        return jsonify({"ok": False, "msg": "Key expired"}), 410

    # not used yet -> bind hwid & name
    if not doc.get("used"):
        update = {"$set": {"hwid": hwid, "used": True}}
        if name:
            update["$set"]["name"] = name
        keys_col.update_one({"key": key}, update)
        rem = remaining_string(doc["expires_at"])
        return jsonify({"ok": True, "msg": f"welcome {name or doc.get('name','Guest')}\\nRemaining Time: {rem}"}), 200

    # used: check hwid match
    if doc.get("hwid") == hwid:
        rem = remaining_string(doc["expires_at"])
        return jsonify({"ok": True, "msg": f"welcome {doc.get('name','Guest')}\\nRemaining Time: {rem}"}), 200
    else:
        rem = remaining_string(doc["expires_at"])
        return jsonify({"ok": False, "msg": f"This key used by another hwid!\\nRemaining Time: {rem}"}), 403

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
