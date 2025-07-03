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
        # Verificar si el rol existe en la tabla rol
        cur.execute("SELECT 1 FROM rol WHERE nombreRol = %s", (role,))
        if not cur.fetchone():
            conn.close()
            return jsonify({"error": f"Rol '{role}' no válido. Por favor, corrija el rol o regístrelo primero."}), 400
        
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

# ========== CRUD: ROL ==========
@app.route("/roles", methods=["GET"])
def listar_roles():
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM rol")
        roles = cur.fetchall()
    conn.close()
    return jsonify(roles)

@app.route("/roles", methods=["POST"])
def crear_rol():
    data = request.get_json() 
    nombre = data.get("nombreRol")
    if not nombre:
        return jsonify({"error": "nombreRol requerido"}), 400
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO rol (nombreRol) VALUES (%s)", (nombre,))
    conn.commit()
    conn.close()
    return jsonify({"status": "created", "nombreRol": nombre}), 201

@app.route("/roles/<int:id>", methods=["PUT"])
def actualizar_rol(id):
    data = request.json
    nuevo_nombre = data.get("nombreRol")
    if not nuevo_nombre:
        return jsonify({"error": "nombreRol requerido"}), 400
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("UPDATE rol SET nombreRol = %s WHERE id = %s", (nuevo_nombre, id))
    conn.commit()
    conn.close()
    return jsonify({"status": "updated", "id": id, "nombreRol": nuevo_nombre})

@app.route("/roles/<int:id>", methods=["DELETE"])
def eliminar_rol(id):
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM rol WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": id})

# ========== CRUD: SERVICIO ==========
@app.route("/servicios", methods=["GET"])
def listar_servicios_filtrados():
    rol = request.args.get("rol")  # Se obtiene con ?rol=rolsito
    conn = get_conn()
    with conn.cursor() as cur:
        if rol:
            # Subconsulta para obtener id del rol
            cur.execute("SELECT id FROM rol WHERE nombreRol = %s", (rol,))
            row = cur.fetchone()
            if not row:
                conn.close()
                return jsonify([])  # o error 404 si prefieres
            id_rol = row["id"]
            cur.execute("SELECT * FROM servicios WHERE idRol = %s", (id_rol,))
        else:
            cur.execute("SELECT * FROM servicios")
        servicios = cur.fetchall()
    conn.close()
    return jsonify(servicios)

@app.route("/servicios", methods=["POST"])
def crear_servicio():
    data = request.json
    nombre = data.get("nombre")
    ip = data.get("ip")
    id_rol = data.get("idRol")
    if not nombre or not ip or not id_rol:
        return jsonify({"error": "nombre, ip e idRol son requeridos"}), 400
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO servicios (nombre, ip, idRol) VALUES (%s, %s, %s)", (nombre, ip, id_rol))
    conn.commit()
    conn.close()
    return jsonify({"status": "created", "nombre": nombre, "ip": ip, "idRol": id_rol}), 201

@app.route("/servicios/<int:id>", methods=["PUT"])
def actualizar_servicio(id):
    data = request.json
    nombre = data.get("nombre")
    ip = data.get("ip")
    id_rol = data.get("idRol")
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE servicios SET nombre = %s, ip = %s, idRol = %s WHERE id = %s
        """, (nombre, ip, id_rol, id))
    conn.commit()
    conn.close()
    return jsonify({"status": "updated", "id": id})

@app.route("/servicios/<int:id>", methods=["DELETE"])
def eliminar_servicio(id):
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM servicios WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": id})

# ========== CRUD: LOGS ==========
@app.route("/logs", methods=["GET"])
def listar_logs():
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM logs ORDER BY fecha DESC")
        logs = cur.fetchall()
    conn.close()
    return jsonify(logs)

@app.route("/logs", methods=["POST"])
def registrar_log():
    data = request.json
    username = data.get("username")
    rol = data.get("rol")
    mac = data.get("mac")
    ip = data.get("ip")

    if not username or not rol:
        return jsonify({"error": "username y rol son requeridos"}), 400

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO logs (username, rol, mac, ip) 
            VALUES (%s, %s, %s, %s)
        """, (username, rol, mac, ip))
    conn.commit()
    conn.close()
    return jsonify({"status": "log registrado"}), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010)



