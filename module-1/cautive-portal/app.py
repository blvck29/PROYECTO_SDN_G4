from flask import Flask, render_template, request
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AccessAccept
import socket 

app = Flask(__name__)


# Configuración del servidor RADIUS
RADIUS_SERVER = "freeradius"  # nombre del contenedor o IP en la red Docker
RADIUS_SECRET = b"testing123"
RADIUS_PORT = 1812

# Ruta del archivo dictionary adaptado
DICTIONARY_PATH = "dictionary"

@app.route("/portal", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        print("=== POST recibido en /portal ===")
        print("request.form:", request.form)

        username = request.form["username"]
        password = request.form["password"]
        ip = request.form["ip"]
        mac = request.form["mac"]

        print("Usuario:", username, flush=True)
        print("Contraseña:", "*" * len(password), flush=True)
        print("MAC: ", mac, flush=True)
        print("IP: ", ip, flush=True)

        if not username or not password or not mac:
            print("❌ Faltan campos en el formulario.")
            return "Error: faltan campos", 400

       # IP del cliente que accede al portal
        client_ip = request.remote_addr or "0.0.0.0"

        print("IP del cliente:", client_ip)

        #Cliente RADIUS
        try:
            client = Client(server=RADIUS_SERVER, secret=RADIUS_SECRET, dict=Dictionary(DICTIONARY_PATH))
            client.AuthPort = RADIUS_PORT

            req = client.CreateAuthPacket(code=AccessRequest, User_Name=username)
            req["User-Password"] = req.PwCrypt(password)
            req["Framed-IP-Address"] = client_ip
            req["Calling-Station-Id"] = mac
            req["Framed-IP-Address"] = ip

            print("📡 Enviando solicitud RADIUS...")
            reply = client.SendPacket(req)

            print("Código de respuesta RADIUS:", reply.code)

            if reply.code == AccessAccept:
                print("✅ Autenticación exitosa")
                return render_template("success.html", username=username)
            else:
                print("❌ Acceso denegado por RADIUS")
                return render_template("login.html", error="Acceso denegado por RADIUS")

        except Exception as e:
            print("🚨 Error al contactar con RADIUS:", e)
            return render_template("login.html", error="Error al conectar con el servidor")

    return render_template("login.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

