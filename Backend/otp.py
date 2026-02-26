
from flask import Blueprint, session, redirect, render_template, request, current_app, abort
import requests
import random
import os
import time
import hashlib

otp_bp = Blueprint("otp", __name__)

OTP_EXPIRY = 300  # 5 minutes


def validate_csrf():
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("_csrf_token"):
        return False
    return True

def send_sms_otp(phone, otp):
    url = "https://www.fast2sms.com/dev/bulk"

    payload = {
        "sender_id": "TXTIND",
        "message": f"Your SV Accountax Crew Admin OTP is {otp}. Valid for 5 minutes.",
        "language": "english",
        "route": "q",
        "numbers": phone
    }

    headers = {
        "authorization": os.getenv("FAST2SMS_API_KEY"),
        "Content-Type": "application/json"
    }

    response = requests.post(url, data=payload, headers=headers)
    print("FAST2SMS RESPONSE:", response.text)



@otp_bp.route("/send-otp")
def send_otp():
    # ✅ MUST check admin_temp (NOT is_admin)
    if not session.get("admin_temp"):
        return redirect("/login")

    otp = random.randint(100000, 999999)
    otp_hash = hashlib.sha256(str(otp).encode()).hexdigest()

    session["admin_otp"] = otp_hash
    session["otp_time"] = time.time()

    phone = os.getenv("ADMIN_PHONE")

    # 🔥 DEBUG (MANDATORY)
    print("🔥 SEND OTP ROUTE HIT")
    print("📱 ADMIN PHONE:", phone)
    print("🔐 OTP:", otp)

    send_sms_otp(phone, otp)

    return redirect("/verify-otp")


@otp_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if not session.get("admin_temp"):
        return redirect("/login")

    if request.method == "POST":
        if not validate_csrf():
            abort(403)
        if "otp_time" not in session or "admin_otp" not in session:
            return redirect("/login")

        user_otp = request.form["otp"]
        hashed_input = hashlib.sha256(user_otp.encode()).hexdigest()

        if time.time() - session["otp_time"] > OTP_EXPIRY:
            session.clear()
            return "OTP Expired"

        if hashed_input == session.get("admin_otp"):
            session.pop("admin_otp", None)
            session.pop("otp_time", None)
            session["role"] = "admin"
            session["admin_logged_in"] = True
            session["is_admin"] = True
            session["_boot_id"] = current_app.config["SESSION_BOOT_ID"]
            session["_last_seen"] = int(time.time())
            return redirect("/")

        return "Invalid OTP"

    return render_template("verify_otp.html")
