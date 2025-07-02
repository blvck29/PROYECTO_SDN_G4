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
        username = request.form["username"]
        password = request.form["password"]

       # IP del cliente que accede al portal
        client_ip = request.remote_addr or "0.0.0.0"

        # IP del servidor Flask (NAS-IP)
        server_ip = socket.gethostbyname(socket.gethostname())

        #Cliente RADIUS
        client = Client(server=RADIUS_SERVER, secret=RADIUS_SECRET, dict=Dictionary(DICTIONARY_PATH))
        client.AuthPort = RADIUS_PORT

        #Petición owo
        req = client.CreateAuthPacket(code=AccessRequest, User_Name=username)
        req["User-Password"] = req.PwCrypt(password)  # Encripta usando MD5 con el secret
        req["Framed-IP-Address"] = client_ip          # IP del usuario
        req["NAS-IP-Address"] = server_ip             # IP del servidor Flask

        try:
            reply = client.SendPacket(req)  # Enviar al servidor RADIUS

            if reply.code == AccessAccept:
                return render_template("success.html", username=username)
            else:
                return render_template("login.html", error="Acceso denegado por RADIUS")

        except Exception as e:
            return render_template("login.html", error=f"Error al conectar con el servidor")
        
    return render_template("login.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

