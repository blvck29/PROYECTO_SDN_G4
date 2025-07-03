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
                    print(f"La MAC {mac_address} no tiene attachmentPoint.", flush=True)
        print(f"La MAC {mac_address} no fue encontrada.", flush=True)
    else:
        print(f"[{response.status_code}]", flush=True)
        print(f"Respuesta: {response.text}", flush=True)

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
        url = f"http://10.10.0.10:5010/servicios?rol={rolsito}"  # IP del servicio que expone el API
        resp = requests.get(url)

        if resp.status_code != 200:
            print(f"[!] Error al obtener servicios: {resp.status_code} - {resp.text}", flush=True)
            return

        servicios = resp.json()

        src_dpid, src_port = get_attachment_points(mac)

        if not src_dpid:
            print(f"[!] No se pudo obtener el punto de conexión de {mac}", flush=True)
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
                        print(f"[+] Flow instalado en {flow['switch']} hacia {ip_destino}", flush=True)
                    else:
                        print(f"[!] Error al instalar flow: {r.text}", flush=True)
            else:
                print(f"[!] No se encontró ruta hacia {ip_destino}", flush=True)

    except Exception as e:
        print(f"[!] Error al conectar con la base de datos: {e}", flush=True)
        return []

def registrar_log_evento(username, rol, mac, ip):
    try:
        payload = {
            "username": username,
            "rol": rol,
            "mac": mac,
            "ip": ip
        }
        resp = requests.post("http://10.10.0.10:5010/logs", json=payload)
        if resp.status_code == 201:
            print(f"[LOG] Registro exitoso de acceso de {username}", flush=True)
        else:
            print(f"[LOG] Error al registrar log: {resp.status_code} - {resp.text}", flush=True)
    except Exception as e:
        print(f"[ERROR] Falló la conexión al registrar log: {e}", flush=True)

@app.route('/auth-event', methods=['POST'])
def auth_event():
    client_ip = request.remote_addr
    if client_ip not in ALLOWED_IPS:
        print(f"[!] Rechazada conexión desde IP no autorizada: {client_ip}", flush=True)
        abort(403)

    data = request.get_json()
    username = data.get("User-Name", "")
    role = data.get("Filter-Id", "invitado")
    ip = data.get("ip", "")  # Recibiendo el parámetro ip
    mac = data.get("mac-address", "")
    
    if not mac or not ip:
        print("[!] MAC o IP faltantes en el payload", flush=True)
        return jsonify({"error": "Missing MAC or IP"}), 400

    print(f"[+] Autenticado: {username} como rol {role}", flush=True)
    print(f"   MAC-ADDRESS: {mac}", flush=True)
    print(f"   IP-ADDRESS: {ip}", flush=True)

    # Registrar el log de este evento
    registrar_log_evento(username, role, mac, ip)

    #Lógica para obtener los servicios permitidos según su rol

    #Roles:  Admin de red, Usuario Administrativo, Docente, Secretaria, Alumno, Invitado (else)
    if role == "admin":
        print(f"[OK] - Autenticado como admin", flush=True)
        obtener_servicios_permitidos_por_rol("admin",mac)
        #os.system("curl -X POST http://controller:8080/apply_admin_flows")
    elif role == "admin_user":
        print(f"[OK] - Autenticado como admin_user", flush=True)
        obtener_servicios_permitidos_por_rol("admin_user",mac)
    elif role == "docente":
        print(f"[OK] - Autenticado como docente", flush=True)
        obtener_servicios_permitidos_por_rol("docente",mac)
    elif role == "secretaria":
        print(f"[OK] - Autenticado como secretaria", flush=True)
        obtener_servicios_permitidos_por_rol("secretaria",mac)
    elif role == "estudiante":
        print(f"[OK] - Autenticado como estudiante", flush=True)
        obtener_servicios_permitidos_por_rol("estudiante",mac)
        #os.system("curl -X POST http://controller:8080/apply_student_flows")
    else:
        print(f"[OK] - Autenticado sin rol - invitado", flush=True)
        #Cambiar lógica rol invitado
        obtener_servicios_permitidos_por_rol("invitado",mac)
        #os.system("curl -X POST http://controller:8080/apply_guest_flows")

    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5015)


