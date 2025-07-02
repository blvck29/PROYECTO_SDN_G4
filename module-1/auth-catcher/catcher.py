# catcher.py
from flask import Flask, request, jsonify, abort
import os
import pymysql
import requests


app = Flask(__name__)

# Solo se aceptarán peticiones desde esta IP (freeradius)
ALLOWED_IPS = ['10.10.0.2']
FLOODLIGHT_URL = "http://10.20.12.161:8080"


#Punto de conexión de un host
def get_attachment_points(mac_address):
    url = f"{FLOODLIGHT_URL}/wm/device/"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        for host in data:
            if mac_address.lower() in [m.lower() for m in host.get("mac", [])]:
                aps = host.get("attachmentPoint", [])
                if aps:
                    punto = aps[0]
                    return punto["switchDPID"], punto["port"]
                else:
                    print(f"La MAC {mac_address} no tiene attachmentPoint.")
        print(f"La MAC {mac_address} no fue encontrada.")
    else:
        print(f"[{response.status_code}]")
        print(f"Respuesta: {response.text}")
    
    return None, None

# Consulta de la ruta
def get_route(src_dpid, src_port, dst_dpid, dst_port):

    url = f"{FLOODLIGHT_URL}/wm/topology/route/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json"
    response = requests.get(url)

    if response.status_code == 200:
        ruta = response.json()
        # DPID y puerto de cada paso
        return [(hop["switch"], hop["port"]["portNumber"]) for hop in ruta]
    return []
#FLOWS :D
def generar_flows_para_ruta(ruta, ip_destino):
    flows = []

    for i, (dpid, port) in enumerate(ruta):
        flow = {
            "switch": dpid,
            "name": f"flow_{dpid}_{ip_destino.replace('.', '_')}_{i}",
            "priority": 1000,
            "eth_type": "0x0800",
            "ipv4_dst": ip_destino,
            "active": "true",
            "hard_timeout": 3600,  #1h owo (BAJARLE PARA LA PRESENTACIÓN XD)
            "idle_timeout": 300,   #5min owo (BAJARLE TMB)
            "actions": f"output={port}"
        }
        flows.append(flow)
    return flows

#Función pa obtener servicios owo
def obtener_servicios_permitidos_por_rol(rolsito, mac):
    try:
        # Conexión a la base de datos (CAMBIAR)
        conexion = pymysql.connect(
            host='localhost',         # o el nombre del servicio en Docker, como 'db'
            user='usuario_db',
            password='clave_db',
            database='db_sdn',
            cursorclass=pymysql.cursors.DictCursor  # Para obtener resultados como diccionarios
        )

        with conexion.cursor() as cursor:
            # Consulta SQL
            sql = "SELECT * FROM servicios WHERE rol = %s"
            cursor.execute(sql, (rolsito,))
            servicios = cursor.fetchall()
        
        conexion.close()
        
        src_dpid, src_port = get_attachment_points(mac)

        if not src_dpid:
            print(f"[!] No se pudo obtener el punto de conexión de {mac}")
            return

        for servicio in servicios:
            dst_dpid = servicio["dpid"]
            dst_port = servicio["puerto"]
            ip_destino = servicio["ip"]

            ruta = get_route(src_dpid, src_port, dst_dpid, dst_port)
            if ruta:
                flows = generar_flows_para_ruta(ruta, ip_destino)
                for flow in flows:
                    r = requests.post(f"{FLOODLIGHT_URL}/wm/staticflowpusher/json", json=flow)
                    if r.status_code == 200:
                        print(f"[+] Flow instalado en {flow['switch']} hacia {ip_destino}")
                    else:
                        print(f"[!] Error al instalar flow: {r.text}")
            else:
                print(f"[!] No se encontró ruta hacia {ip_destino}")

    except Exception as e:
        print(f"[!] Error al conectar con la base de datos: {e}")
        return []

@app.route('/auth-event', methods=['POST'])
def auth_event():
    client_ip = request.remote_addr
    if client_ip not in ALLOWED_IPS:
        print(f"[!] Rechazada conexión desde IP no autorizada: {client_ip}")
        abort(403)

    data = request.get_json()
    username = data.get("User-Name", "")
    role = data.get("Filter-Id", "invitado")
    #IMPORTANTE: NECESITAREMOS QUE LA MAC LA ENVIE RADIUS SINO F    
    mac = data.get("mac-address", "")

    print(f"[+] Autenticado: {username} como rol {role}")   
    
    #Lógica para obtener los servicios permitidos según su rol

    #Roles:  Admin de red, Usuario Administrativo, Docente, Secretaria, Alumno, Invitado (else)
    if role == "admin":
        obtener_servicios_permitidos_por_rol("admin",mac)
        #os.system("curl -X POST http://controller:8080/apply_admin_flows")
    elif role == "admin_user":
        obtener_servicios_permitidos_por_rol("admin_user",mac)
    elif role == "docente":
        obtener_servicios_permitidos_por_rol("docente",mac)
    elif role == "secretaria":
        obtener_servicios_permitidos_por_rol("secretaria",mac)
    elif role == "estudiante":
        obtener_servicios_permitidos_por_rol("estudiante",mac)
        #os.system("curl -X POST http://controller:8080/apply_student_flows")
    else:
        #Cambiar lógica rol invitado
        obtener_servicios_permitidos_por_rol("invitado",mac)
        #os.system("curl -X POST http://controller:8080/apply_guest_flows")
        

    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5015)
