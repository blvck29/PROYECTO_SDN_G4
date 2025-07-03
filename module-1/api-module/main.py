from flask import Flask, request, jsonify
import pymysql

app = Flask(__name__)

def get_conn():
    return pymysql.connect(
        host="10.10.0.3",
        user="radius",
        password="radpass",
        database="radius",
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route("/users", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "invitado")  # default role

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    conn = get_conn()
    with conn.cursor() as cur:
        # Verificar si ya existe
        cur.execute("SELECT 1 FROM radcheck WHERE username = %s", (username,))
        if cur.fetchone():
            conn.close()
            return jsonify({"error": f"user '{username}' already exists"}), 409  # 409 Conflict

        # Insertar nuevo usuario
        cur.execute("""
            INSERT INTO radcheck (username, attribute, op, value)
            VALUES (%s, 'Cleartext-Password', ':=', %s)
        """, (username, password))

        cur.execute("""
            INSERT INTO radreply (username, attribute, op, value)
            VALUES (%s, 'Filter-Id', '=', %s)
        """, (username, role))

    conn.commit()
    conn.close()

    return jsonify({
        "status": "created",
        "username": username,
        "role": role
    }), 201



@app.route("/users/<username>", methods=["GET"])
def get_user(username):
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT value AS password FROM radcheck WHERE username = %s", (username,))
        pw = cur.fetchone()
        cur.execute("SELECT value AS role FROM radreply WHERE username = %s", (username,))
        role = cur.fetchone()
    conn.close()
    if not pw:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"username": username, "password": pw["password"], "role": role["role"] if role else None})

@app.route("/users/<username>", methods=["PUT"])
def update_user(username):
    data = request.json
    new_pw = data.get("password")
    new_role = data.get("role")
    conn = get_conn()
    with conn.cursor() as cur:
        if new_pw:
            cur.execute("UPDATE radcheck SET value = %s WHERE username = %s", (new_pw, username))
        if new_role:
            cur.execute("UPDATE radreply SET value = %s WHERE username = %s", (new_role, username))
    conn.commit()
    conn.close()
    return jsonify({"status": "updated", "user": username})

@app.route("/users/<username>", methods=["DELETE"])
def delete_user(username):
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM radcheck WHERE username = %s", (username,))
        cur.execute("DELETE FROM radreply WHERE username = %s", (username,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "user": username})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010)

