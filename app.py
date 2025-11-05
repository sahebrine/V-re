# app_api.py
from flask import Flask, request, jsonify
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta
import os
import secrets

# ---------- CONFIG ----------
MONGO_URI = os.environ.get(
    "MONGO_URI",
    "mongodb+srv://sahebrine_db_user:7XlD1xWNVbFvACFh@cluster0.wemjued.mongodb.net/?retryWrites=true&w=majority"
)
DB_NAME = os.environ.get("DB_NAME", "sahebrine_db")
COL_NAME = os.environ.get("COL_NAME", "vurekeys")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-me-to-secure-token")
KEY_PREFIX = "VURE"

# ---------- INIT ----------
app = Flask(__name__)
client = MongoClient(MONGO_URI, server_api=ServerApi("1"))
db = client[DB_NAME]
keys_col = db[COL_NAME]

# ---------- HELPERS ----------
def now_utc():
    return datetime.now(timezone.utc)

def iso(dt: datetime):
    """Return ISO string in UTC for a datetime (aware or naive treated as UTC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def parse_iso(s):
    """Parse ISO datetime string to an aware datetime in UTC."""
    if isinstance(s, datetime):
        if s.tzinfo is None:
            return s.replace(tzinfo=timezone.utc)
        return s.astimezone(timezone.utc)
    # Python 3.11+ supports fromisoformat for offsets; ensure timezone aware
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def remaining_string(expire_at):
    """
    Accepts expire_at as ISO string or datetime, returns human readable remaining time.
    Example outputs: '3d 4h 12m' or 'Expired' or 'Unknown'
    """
    try:
        if not expire_at:
            return "Unknown"
        if isinstance(expire_at, str):
            exp_dt = parse_iso(expire_at)
        elif isinstance(expire_at, datetime):
            exp_dt = exp_at = expire_at
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            exp_dt = exp_dt.astimezone(timezone.utc)
        else:
            return "Unknown"

        remaining = (exp_dt - now_utc()).total_seconds()
        if remaining <= 0:
            return "Expired"

        minutes, seconds = divmod(int(remaining), 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)

        parts = []
        if days: parts.append(f"{days}d")
        if hours: parts.append(f"{hours}h")
        if minutes: parts.append(f"{minutes}m")
        return " ".join(parts) if parts else "less than 1m"
    except Exception:
        return "Unknown"

def cleanup_expired():
    """Delete keys that have expiry <= now. Returns number deleted."""
    cur_iso = iso(now_utc())
    res = keys_col.delete_many({"expires_at": {"$lte": cur_iso}})
    return res.deleted_count

def require_admin():
    token = request.headers.get("X-Admin-Token") or request.args.get("admin_token")
    return token == ADMIN_TOKEN

def generate_key(duration_str):
    """duration_str example: '1 month' or '30 day' or '60 minute'"""
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
    data = request.get_json(force=True) or {}
    name = data.get("name", "default")
    duration = data.get("duration", "1 month")  # default 1 month
    try:
        key, _ = generate_key(duration)
    except Exception:
        return jsonify({"ok": False, "msg": "Invalid duration format"}), 400

    doc = {
        "key": key,
        "name": name,
        "duration": duration,
        "expires_at": None,
        "hwid": None,
        "used": False,
        "created_at": iso(now_utc())
    }
    keys_col.insert_one(doc)
    
    return jsonify({"ok": True, "key": key}), 201

@app.route("/api/delete_key", methods=["POST"])
def api_delete_key():
    if not require_admin():
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    cleanup_expired()
    data = request.get_json(force=True) or {}
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
    docs = list(keys_col.find({}, {"_id": 0}).sort("created_at", -1))
    out = []
    for d in docs:
        expires_at = d.get("expires_at")
        rem = remaining_string(expires_at)
        status = "Active" if rem != "Expired" and rem != "Unknown" else "Expired"
        used = bool(d.get("used"))
        out.append({
            "key": d.get("key"),
            "name": d.get("name"),
            "expires_at": expires_at,
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
    data = request.get_json(force=True) or {}
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
    data = request.get_json(force=True) or {}
    key = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()
    name = data.get("name", "").strip() or None

    if not key or not hwid:
        return jsonify({"ok": False, "msg": "Missing key or hwid"}), 400

    doc = keys_col.find_one({"key": key})
    if not doc:
        return jsonify({"ok": False, "msg": "Invalid key"}), 404

    # نجيب المدة أولاً
    duration = doc.get("duration", 30)  # مدة افتراضية مثلاً 30 يوم لو مافيه

    expires_at = doc.get("expires_at")

    # ✅ إذا المفتاح جديد وما فيه expires_at، أنشئ واحد جديد
    if not expires_at:
        _, expires_iso = generate_key(duration)
        keys_col.update_one({"key": key}, {"$set": {"expires_at": expires_iso}})
        expires_at = expires_iso  # خزن القيمة بعد التحديث

    # نحاول نحولها لتاريخ
    try:
        exp_dt = parse_iso(expires_at)
    except Exception:
        return jsonify({"ok": False, "msg": "Corrupted key data"}), 400

    remaining_seconds = (exp_dt - now_utc()).total_seconds()
    if remaining_seconds <= 0:
        keys_col.delete_one({"key": key})
        return jsonify({"ok": False, "msg": "Key expired", "remaining": "Expired"}), 410

    stored_hwid = doc.get("hwid")

    # ✅ تحقق من hwid (ما يحذف لو كان جديد)
    if stored_hwid and stored_hwid != hwid:
        return jsonify({"ok": False, "msg": "This key used by another hwid!"}), 403

    # أول استخدام للمفتاح: خزّن HWID واسم المستخدم
    if not stored_hwid:
        update = {"$set": {"hwid": hwid, "used": True}}
        if name:
            update["$set"]["name"] = name
        keys_col.update_one({"key": key}, update)
        display_name = name or doc.get("name", "Guest")
    else:
        display_name = doc.get("name", name) or "Guest"

    return jsonify({
        "ok": True,
        "msg": f"Welcome {display_name}",
        "expires_at": expires_at
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)


