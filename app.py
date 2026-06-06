from flask import Flask, request, redirect, session, render_template_string
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
    return psycopg2.connect(
        host=DB_CONFIG["host"],
        database=DB_CONFIG["database"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"]
    )


@app.route("/")
def index():

    with open("login.html", "r", encoding="utf-8") as f:
        return f.read()


@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username")
    password = request.form.get("password")

    try:

        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT username, role
            FROM users
            WHERE username=%s
            AND password_hash=%s
        """, (username, password))

        user = cur.fetchone()

        cur.close()
        conn.close()

        if user:

            session["username"] = user[0]
            session["role"] = user[1]

            return redirect("/dashboard")

        return """
        <h2>Invalid Username / Password</h2>
        <a href="/">Back</a>
        """

    except Exception as e:
        return str(e)


@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect("/")

    with open("dashboard.html", "r", encoding="utf-8") as f:
        html = f.read()

    return render_template_string(
        html,
        username=session["username"],
        role=session["role"]
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)