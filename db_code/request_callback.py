from flask import Flask, request, redirect, flash,render_template
from datetime import datetime
from app import app,db,cursor



# =============================
# USER CALLBACK ROUTE
# =============================
@app.route("/request-callback", methods=["POST"])
def request_callback():
    phone = request.form.get("phone")
    email = request.form.get("email")

    # Validation
    if not phone and not email:
        flash("Please provide phone number or email", "error")
        return redirect(request.referrer)

    save_callback_request(phone, email)
    notify_admin(phone, email)

    flash("Callback request submitted successfully!", "success")
    return redirect(request.referrer)


# =============================
# SAVE TO DATABASE
# =============================
def save_callback_request(phone, email):
    cursor.execute("""
        INSERT INTO callback_requests (phone, email, created_at, status)
        VALUES (%s, %s, %s, %s)
    """, (phone, email, datetime.now(), "pending"))
    db.commit()


# =============================
# ADMIN NOTIFICATION (TEMP)
# =============================
def notify_admin(phone, email):
    print("📞 NEW CALLBACK REQUEST")
    print("Phone:", phone or "N/A")
    print("Email:", email or "N/A")


@app.route("/admin/callbacks")
def admin_callbacks():
    cursor.execute("""
        SELECT id, phone, email, created_at, status
        FROM callback_requests
        ORDER BY created_at DESC
    """)
    callbacks = cursor.fetchall()
    return render_template("admin_callbacks.html", callbacks=callbacks)

@app.route("/admin/callbacks/update/<int:id>", methods=["POST"])
def update_callback_status(id):
    status = request.form.get("status")

    cursor.execute("""
        UPDATE callback_requests
        SET status = %s
        WHERE id = %s
    """, (status, id))
    db.commit()

    flash("Status updated", "success")
    return redirect("/admin/callbacks")
print("✅ request_callback routes loaded")
