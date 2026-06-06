from flask import Flask, request, redirect, session, render_template
import psycopg2

app = Flask(__name__)
app.secret_key = "griddocs_secret"

DB_CONFIG = {
    "host": "localhost",
    "database": "griddocs",
    "user": "postgres",
    "password": "admin"
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

# ---------- Helper: Build category tree (nested dicts) ----------
def build_category_tree(categories_list):
    """Convert flat list of (id, name, parent_id) into nested dicts with children.
       Assumes list is already sorted by display_order."""
    nodes = {}
    for cat in categories_list:
        cat_id, name, parent_id = cat
        nodes[cat_id] = {
            'id': cat_id,
            'name': name,
            'parent_id': parent_id,
            'children': []
        }
    roots = []
    for node in nodes.values():
        if node['parent_id'] is None or node['parent_id'] not in nodes:
            roots.append(node)
        else:
            nodes[node['parent_id']]['children'].append(node)
    # Already ordered by display_order from SQL
    roots.sort(key=lambda x: x['id'])
    return roots

def get_user_category_tree(user_id):
    """Return nested tree of categories that the user has permission to see."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.id, c.name, c.parent_id
        FROM categories c
        JOIN user_category_permissions ucp ON c.id = ucp.category_id
        WHERE ucp.user_id = %s
        ORDER BY c.display_order
    """, (user_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return build_category_tree(rows)

# ---------- Routes ----------
@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, role FROM users WHERE username=%s AND password_hash=%s", (username, password))
        user = cur.fetchone()
        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[2]

            # Fetch user's category permissions for sidebar (flat list)
            cur.execute("""
                SELECT c.id, c.name
                FROM categories c
                JOIN user_category_permissions ucp ON c.id = ucp.category_id
                WHERE ucp.user_id = %s
                ORDER BY c.display_order
            """, (user[0],))
            session["user_categories_flat"] = cur.fetchall()

            cur.close()
            conn.close()
            return redirect("/dashboard")
        return "<h2>Invalid Credentials</h2><a href='/'>Back</a>"
    except Exception as e:
        return str(e)

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/")
    tree = get_user_category_tree(session["user_id"])
    return render_template("dashboard.html",
                           username=session["username"],
                           role=session["role"],
                           category_tree=tree)

@app.route("/category/<int:cat_id>")
def view_category(cat_id):
    if "username" not in session:
        return redirect("/")
    user_cats = session.get("user_categories_flat", [])
    if cat_id not in [c[0] for c in user_cats]:
        return "Access Denied", 403
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT name FROM categories WHERE id = %s", (cat_id,))
    cat = cur.fetchone()
    cur.close()
    conn.close()
    return render_template("category_content.html",
                           category_name=cat[0] if cat else "Category",
                           username=session["username"],
                           role=session["role"])

@app.route("/users")
def users():
    if session.get("role") != "admin":
        return redirect("/")
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, full_name, username, role FROM users ORDER BY id")
    users_data = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("users.html", users=users_data,
                           username=session["username"], role=session["role"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/permissions")
def permissions():
    if session.get("role") != "admin":
        return redirect("/")
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.username, p.permission_name
        FROM user_permissions up
        JOIN users u ON u.id = up.user_id
        JOIN permissions p ON p.id = up.permission_id
        ORDER BY u.username
    """)
    data = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("permissions.html", permissions=data,
                           username=session["username"], role=session["role"])

@app.route("/user-permissions/<int:user_id>")
def user_permissions(user_id):
    if session.get("role") != "admin":
        return redirect("/")
    conn = get_connection()
    cur = conn.cursor()

    # User info
    cur.execute("SELECT id, full_name, username FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()

    # Regular permissions
    cur.execute("SELECT id, permission_name FROM permissions ORDER BY permission_name")
    permissions = cur.fetchall()
    cur.execute("SELECT permission_id FROM user_permissions WHERE user_id=%s", (user_id,))
    assigned_perms = [row[0] for row in cur.fetchall()]

    # Category permissions
    cur.execute("SELECT id, name, parent_id FROM categories ORDER BY display_order")
    all_cats = cur.fetchall()
    cur.execute("SELECT category_id FROM user_category_permissions WHERE user_id=%s", (user_id,))
    assigned_cats = [row[0] for row in cur.fetchall()]

    cur.close()
    conn.close()

    # Build category tree
    category_tree = build_category_tree(all_cats)

    return render_template("user_permissions.html",
                           user=user,
                           permissions=permissions,
                           assigned_perms=assigned_perms,
                           category_tree=category_tree,
                           assigned_cats=assigned_cats,
                           username=session["username"],
                           role=session["role"])

@app.route("/save-permissions/<int:user_id>", methods=["POST"])
def save_permissions(user_id):
    if session.get("role") != "admin":
        return "Access Denied", 403

    selected_perms = request.form.getlist("permissions")
    selected_cats = request.form.getlist("categories")

    conn = get_connection()
    cur = conn.cursor()

    # Save regular permissions
    cur.execute("DELETE FROM user_permissions WHERE user_id=%s", (user_id,))
    for pid in selected_perms:
        cur.execute("INSERT INTO user_permissions (user_id, permission_id) VALUES (%s,%s)", (user_id, pid))

    # Save category permissions
    cur.execute("DELETE FROM user_category_permissions WHERE user_id=%s", (user_id,))
    for cat_id in selected_cats:
        cur.execute("INSERT INTO user_category_permissions (user_id, category_id) VALUES (%s,%s)", (user_id, cat_id))

    conn.commit()
    cur.close()
    conn.close()

    # If admin changed his own category permissions, update session sidebar list
    if user_id == session.get("user_id"):
        conn2 = get_connection()
        cur2 = conn2.cursor()
        cur2.execute("""
            SELECT c.id, c.name
            FROM categories c
            JOIN user_category_permissions ucp ON c.id = ucp.category_id
            WHERE ucp.user_id = %s
            ORDER BY c.display_order
        """, (user_id,))
        session["user_categories_flat"] = cur2.fetchall()
        cur2.close()
        conn2.close()

    return redirect(f"/user-permissions/{user_id}")

# ---------- Category Management (Admin only) ----------
@app.route("/categories")
def categories():
    if session.get("role") != "admin":
        return redirect("/")
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.id, c.name, c.parent_id, p.name as parent_name, c.display_order
        FROM categories c
        LEFT JOIN categories p ON c.parent_id = p.id
        ORDER BY c.display_order, c.id
    """)
    cat_list = cur.fetchall()
    cur.execute("SELECT id, username FROM users ORDER BY username")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("categories.html", categories=cat_list, users=users,
                           username=session["username"], role=session["role"])

@app.route("/categories/add", methods=["POST"])
def add_category():
    if session.get("role") != "admin":
        return "Access Denied", 403
    name = request.form.get("name")
    parent_id = request.form.get("parent_id") or None
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(MAX(display_order), -1) + 1 FROM categories")
    new_order = cur.fetchone()[0]
    cur.execute("INSERT INTO categories (name, parent_id, display_order) VALUES (%s, %s, %s)",
                (name, parent_id, new_order))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/categories")

@app.route("/categories/delete/<int:cat_id>")
def delete_category(cat_id):
    if session.get("role") != "admin":
        return "Access Denied", 403
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM categories WHERE id = %s", (cat_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/categories")

@app.route("/categories/order", methods=["POST"])
def update_category_order():
    if session.get("role") != "admin":
        return "Access Denied", 403
    data = request.get_json()
    ordered_ids = data.get("ordered_ids", [])
    conn = get_connection()
    cur = conn.cursor()
    for idx, cat_id in enumerate(ordered_ids):
        cur.execute("UPDATE categories SET display_order = %s WHERE id = %s", (idx, cat_id))
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(debug=True)