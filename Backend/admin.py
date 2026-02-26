
from flask import Blueprint, session, redirect, render_template, request, abort, Response
from functools import wraps
from db import get_db_connection, release_db_connection
import psycopg2
import csv
import io
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
ROWS_PER_PAGE = 20


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin" or not session.get("admin_logged_in"):
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


def validate_csrf():
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("_csrf_token"):
        abort(403)


def get_page():
    raw = (request.args.get("page") or "1").strip()
    try:
        page = int(raw)
    except ValueError:
        page = 1
    return max(page, 1)


def safe_next_redirect(default_path, allowed_prefix, op_status=None):
    next_url = (request.form.get("next_url") or "").strip()
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = default_path

    parts = urlsplit(next_url)
    path = parts.path or default_path
    if not path.startswith(allowed_prefix):
        path = default_path

    query_items = [(k, v) for (k, v) in parse_qsl(parts.query, keep_blank_values=True) if k != "op_status"]
    if op_status:
        query_items.append(("op_status", op_status))

    sanitized = urlunsplit(("", "", path, urlencode(query_items, doseq=True), ""))
    return redirect(sanitized)


def get_callback_filters():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "all").strip().lower()
    allowed_status = {"pending", "called", "closed"}

    where = []
    params = []

    if q:
        like = f"%{q}%"
        where.append(
            "(COALESCE(name, '') ILIKE %s OR COALESCE(service, '') ILIKE %s OR "
            "COALESCE(phone, '') ILIKE %s OR COALESCE(email, '') ILIKE %s)"
        )
        params.extend([like, like, like, like])

    if status in allowed_status:
        where.append("status = %s")
        params.append(status)
    else:
        status = "all"

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    return q, status, where_sql, params


def get_business_filters():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "all").strip().upper()
    allowed_status = {"NEW", "CONTACTED", "CONVERTED"}

    where = []
    params = []

    if q:
        like = f"%{q}%"
        where.append(
            "(COALESCE(business_name, '') ILIKE %s OR COALESCE(owner_name, '') ILIKE %s OR "
            "COALESCE(email, '') ILIKE %s OR COALESCE(phone, '') ILIKE %s OR "
            "COALESCE(city, '') ILIKE %s OR COALESCE(services, '') ILIKE %s)"
        )
        params.extend([like, like, like, like, like, like])

    if status in allowed_status:
        where.append("status = %s")
        params.append(status)
    else:
        status = "all"

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    return q, status, where_sql, params


@admin_bp.route("/callbacks")
@admin_required
def admin_callbacks():
    q, status_filter, where_sql, params = get_callback_filters()
    page = get_page()
    offset = (page - 1) * ROWS_PER_PAGE

    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return render_template(
            "admin_callbacks.html",
            callbacks=[],
            db_error=True,
            q=q,
            status_filter=status_filter,
            page=1,
            has_prev=False,
            has_next=False,
            rows_per_page=ROWS_PER_PAGE
        )

    try:
        cur = conn.cursor()
        cur.execute(f"""
            SELECT id, name, service, phone, email, created_at, status
            FROM callback_requests
            {where_sql}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, [*params, ROWS_PER_PAGE + 1, offset])
        callbacks = cur.fetchall()
        has_next = len(callbacks) > ROWS_PER_PAGE
        if has_next:
            callbacks = callbacks[:ROWS_PER_PAGE]
        has_prev = page > 1
        cur.close()
    except psycopg2.OperationalError:
        return render_template(
            "admin_callbacks.html",
            callbacks=[],
            db_error=True,
            q=q,
            status_filter=status_filter,
            page=1,
            has_prev=False,
            has_next=False,
            rows_per_page=ROWS_PER_PAGE
        )
    finally:
        release_db_connection(conn)

    return render_template(
        "admin_callbacks.html",
        callbacks=callbacks,
        q=q,
        status_filter=status_filter,
        page=page,
        has_prev=has_prev,
        has_next=has_next,
        rows_per_page=ROWS_PER_PAGE
    )


@admin_bp.route("/callbacks/export")
@admin_required
def export_callbacks():
    q, status_filter, where_sql, params = get_callback_filters()

    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return redirect("/admin/callbacks?op_status=db_error")

    try:
        cur = conn.cursor()
        cur.execute(f"""
            SELECT name, service, phone, email, created_at, status
            FROM callback_requests
            {where_sql}
            ORDER BY created_at DESC
        """, params)
        rows = cur.fetchall()
        cur.close()
    except psycopg2.OperationalError:
        return redirect("/admin/callbacks?op_status=db_error")
    finally:
        release_db_connection(conn)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Service", "Phone", "Email", "Requested At", "Status"])
    writer.writerows(rows)

    filename = "callback_requests.csv"
    if q or status_filter != "all":
        filename = "callback_requests_filtered.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@admin_bp.route("/callbacks/update/<int:id>", methods=["POST"])
@admin_required
def update_callback_status(id):
    validate_csrf()
    status = request.form.get("status")

    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return safe_next_redirect("/admin/callbacks", "/admin/callbacks", "db_error")

    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE callback_requests
            SET status = %s
            WHERE id = %s
        """, (status, id))
        conn.commit()
        cur.close()
    except psycopg2.OperationalError:
        return safe_next_redirect("/admin/callbacks", "/admin/callbacks", "db_error")
    finally:
        release_db_connection(conn)

    return safe_next_redirect("/admin/callbacks", "/admin/callbacks")


@admin_bp.route("/callbacks/delete/<int:id>", methods=["POST"])
@admin_required
def delete_callback(id):
    validate_csrf()

    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return safe_next_redirect("/admin/callbacks", "/admin/callbacks", "db_error")

    try:
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM callback_requests
            WHERE id = %s
        """, (id,))
        conn.commit()
        cur.close()
    except psycopg2.OperationalError:
        conn.rollback()
        return safe_next_redirect("/admin/callbacks", "/admin/callbacks", "db_error")
    finally:
        release_db_connection(conn)

    return safe_next_redirect("/admin/callbacks", "/admin/callbacks")


@admin_bp.route("/logout")
def admin_logout():
    session.clear()
    return redirect("/")

@admin_bp.route("/registrations")
@admin_required
def admin_registrations():
    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return redirect("/admin/dashboard?op_status=db_error")

    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, email, created_at
            FROM users
            ORDER BY created_at DESC
        """)
        users = cur.fetchall()
        cur.close()
    except psycopg2.OperationalError:
        return redirect("/admin/dashboard?op_status=db_error")
    finally:
        release_db_connection(conn)

    return render_template("business_registrations.html", users=users)

@admin_bp.route("/businesses")
@admin_required
def admin_business():
    q, status_filter, where_sql, params = get_business_filters()
    page = get_page()
    offset = (page - 1) * ROWS_PER_PAGE

    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return render_template(
            "admin_businesses.html",
            businesses=[],
            db_error=True,
            q=q,
            status_filter=status_filter,
            page=1,
            has_prev=False,
            has_next=False,
            rows_per_page=ROWS_PER_PAGE
        )

    try:
        cur = conn.cursor()
        cur.execute(f"""
            SELECT 
                id,
                business_name,
                business_type,
                services,
                owner_name,
                email,
                phone,
                city,
                status
            FROM business_registrations
            {where_sql}
            ORDER BY id DESC
            LIMIT %s OFFSET %s
        """, [*params, ROWS_PER_PAGE + 1, offset])
        businesses = cur.fetchall()
        has_next = len(businesses) > ROWS_PER_PAGE
        if has_next:
            businesses = businesses[:ROWS_PER_PAGE]
        has_prev = page > 1
        cur.close()
    except psycopg2.OperationalError:
        return render_template(
            "admin_businesses.html",
            businesses=[],
            db_error=True,
            q=q,
            status_filter=status_filter,
            page=1,
            has_prev=False,
            has_next=False,
            rows_per_page=ROWS_PER_PAGE
        )
    finally:
        release_db_connection(conn)

    return render_template(
        "admin_businesses.html",
        businesses=businesses,
        q=q,
        status_filter=status_filter,
        page=page,
        has_prev=has_prev,
        has_next=has_next,
        rows_per_page=ROWS_PER_PAGE
    )


@admin_bp.route("/businesses/export")
@admin_required
def export_businesses():
    q, status_filter, where_sql, params = get_business_filters()

    try:
        conn = get_db_connection()
    except psycopg2.OperationalError:
        return redirect("/admin/businesses?op_status=db_error")

    try:
        cur = conn.cursor()
        cur.execute(f"""
            SELECT
                business_name,
                business_type,
                services,
                owner_name,
                email,
                phone,
                city,
                status
            FROM business_registrations
            {where_sql}
            ORDER BY id DESC
        """, params)
        rows = cur.fetchall()
        cur.close()
    except psycopg2.OperationalError:
        return redirect("/admin/businesses?op_status=db_error")
    finally:
        release_db_connection(conn)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Business", "Type", "Services", "Owner", "Email", "Phone", "City", "Status"])
    writer.writerows(rows)

    filename = "business_registrations.csv"
    if q or status_filter != "all":
        filename = "business_registrations_filtered.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
