# app_api.py
from flask import Flask, request, jsonify, abort
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta
import os
import secrets

# ---------- CONFIG ----------

MONGO_URI = "mongodb+srv://sahebrine_db_user:7XlD1xWNVbFvACFh@cluster0.wemjued.mongodb.net/?retryWrites=true&w=majority"
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
    """حذف المفاتيح التي انتهت صلاحيتها الآن"""
    cur = now_utc()
    res = keys_col.delete_many({"expires_at": {"$lte": cur.isoformat()}})
    return res.deleted_count
def require_admin():
    token = request.headers.get("X-Admin-Token") or request.args.get("admin_token")
    return token == ADMIN_TOKEN

def generate_key(duration_str):
    """duration_str مثال: '1 month' أو '30 day' أو '60 minute'"""
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

def format_remaining_time(seconds):
    if seconds <= 0:
        return "Expired"
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts = []
    if days: parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    if minutes: parts.append(f"{minutes}m")
    return " ".join(parts) if parts else "less than 1m"

@app.route("/api/check_key", methods=["POST"])
def check_key():
    data = request.get_json(force=True)
    key = data.get("key")
    hwid = data.get("hwid")
    name = data.get("name", "Unknown")

    if not key or not hwid:
        return jsonify({"status": "missing parameters"}), 400

    k = db.keys.find_one({"key": key})
    if not k:
        return jsonify({"status": "invalid key"}), 404

    # حساب الوقت المتبقي
    expire_at = k.get("expire_at")
    if not expire_at:
        return jsonify({"status": "invalid key"}), 404

    remaining_seconds = (expire_at - datetime.utcnow()).total_seconds()

    # إذا انتهى الوقت، نحذف المفتاح فورًا
    if remaining_seconds <= 0:
        db.keys.delete_one({"key": key})
        return jsonify({
            "status": "invalid key",
        }), 410

    remaining = format_remaining_time(remaining_seconds)

    # التحقق من الـ HWID
    stored_hwid = k.get("hwid")
    if stored_hwid and stored_hwid != hwid:
        return jsonify({
            "status": "This key is used by another hwid!",
        }), 403

    # إذا ما كان عنده hwid، نسجله له لأول مرة
    if not stored_hwid:
        db.keys.update_one({"key": key}, {"$set": {
            "hwid": hwid,
            "name": name
        }})

    # رجع له رسالة الترحيب والمدة المتبقية
    return jsonify({
        "status": f"welcome {k.get('name', name)}",
        "remaining": remaining
    }), 200
# ---------- RUN ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
