from flask import Flask, request, jsonify
import pymysql
import requests
import time
import logging
from requests.exceptions import ConnectionError, Timeout, RequestException

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

FLOODLIGHT_URL = "http://192.168.201.200:8080"  # Cambia si tu controlador tiene otra IP
PORTAL_IP = "10.0.0.3"                     # IP del servidor donde está el portal cautivo
PORTAL_TCP_PORT = 5000

def verificar_controlador():
    """
    Verifica si el controlador Floodlight está disponible
    """
    try:
        url = f"{FLOODLIGHT_URL}/wm/core/controller/summary/json"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            logger.info("✓ Controlador Floodlight disponible")
            return True
        else:
            logger.error(f"✗ Controlador responde con código {response.status_code}")
            return False
    except ConnectionError:
        logger.error("✗ No se puede conectar al controlador Floodlight")
        logger.error(f"  Verificar que esté ejecutándose en {FLOODLIGHT_URL}")
        return False
    except Timeout:
        logger.error("✗ Timeout al conectar con el controlador")
        return False
    except Exception as e:
        logger.error(f"✗ Error inesperado: {e}")
        return False

def get_conn():
    return pymysql.connect(
        host="10.10.0.3",
        user="radius",
        password="radpass",
        database="radius",
        cursorclass=pymysql.cursors.DictCursor
    )

def get_attachment_points(mac_address):
    """
    Obtiene los puntos de conexión de una MAC con manejo de errores
    """
    try:
        url = f"{FLOODLIGHT_URL}/wm/device/"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            for host in data:
                if mac_address.lower() in [m.lower() for m in host.get("mac", [])]:
                    aps = host.get("attachmentPoint", [])
                    if aps:
                        punto = aps[0]
                        logger.info(f"✓ MAC {mac_address} encontrada en {punto['switchDPID']}:{punto['port']}")
                        return punto["switchDPID"], punto["port"]
                    else:
                        logger.warning(f"⚠ La MAC {mac_address} no tiene attachmentPoint")
            logger.warning(f"⚠ La MAC {mac_address} no fue encontrada")
        else:
            logger.error(f"✗ Error al obtener dispositivos: {response.status_code}")
            logger.error(f"  Respuesta: {response.text}")
    except ConnectionError:
        logger.error("✗ No se puede conectar al controlador para obtener dispositivos")
    except Timeout:
        logger.error("✗ Timeout al obtener dispositivos del controlador")
    except Exception as e:
        logger.error(f"✗ Error inesperado en get_attachment_points: {e}")
    
    return None, None

def limpiar_flows_existentes():
    """
    Limpia todos los flows existentes para evitar conflictos
    """
    try:
        logger.info("🧹 Limpiando flows existentes...")
        
        # Método 1: Intentar con DELETE (algunos controladores lo soportan)
        response = requests.delete(f"{FLOODLIGHT_URL}/wm/staticflowpusher/clear/all/json", timeout=10)
        
        if response.status_code == 200:
            logger.info("✓ Flows existentes limpiados con DELETE")
            time.sleep(2)  # Esperar a que se apliquen los cambios
            return True
        
        # Método 2: Si DELETE no funciona, intentar con POST
        logger.warning("⚠ DELETE no soportado, intentando con POST...")
        response = requests.post(f"{FLOODLIGHT_URL}/wm/staticflowpusher/clear/all/json", timeout=10)
        
        if response.status_code == 200:
            logger.info("✓ Flows existentes limpiados con POST")
            time.sleep(2)  # Esperar a que se apliquen los cambios
            return True
        
        # Método 3: Si ambos fallan, listar y eliminar flows individuales
        logger.warning("⚠ POST tampoco funciona, listando flows individuales...")
        
        # Obtener lista de flows
        response = requests.get(f"{FLOODLIGHT_URL}/wm/staticflowpusher/list/all/json", timeout=10)
        
        if response.status_code == 200:
            flows_data = response.json()
            flows_eliminados = 0
            
            # Eliminar flows por switch
            for switch_id, flows in flows_data.items():
                if isinstance(flows, dict):
                    for flow_name in flows.keys():
                        try:
                            # Eliminar flow individual
                            delete_url = f"{FLOODLIGHT_URL}/wm/staticflowpusher/json"
                            delete_payload = {
                                "switch": switch_id,
                                "name": flow_name
                            }
                            del_response = requests.delete(delete_url, json=delete_payload, timeout=5)
                            
                            if del_response.status_code == 200:
                                flows_eliminados += 1
                                logger.info(f"  ✓ Flow {flow_name} eliminado del switch {switch_id}")
                            else:
                                logger.warning(f"  ⚠ No se pudo eliminar flow {flow_name}: {del_response.status_code}")
                                
                        except Exception as e:
                            logger.warning(f"  ⚠ Error eliminando flow {flow_name}: {e}")
                            continue
                        
                        time.sleep(0.1)  # Pequeña pausa entre eliminaciones
            
            if flows_eliminados > 0:
                logger.info(f"✓ {flows_eliminados} flows eliminados individualmente")
                time.sleep(2)  # Esperar a que se apliquen los cambios
                return True
            else:
                logger.info("ℹ No se encontraron flows para eliminar")
                return True
        
        else:
            logger.error(f"✗ No se pudo listar flows: {response.status_code}")
            logger.warning("⚠ Continuando sin limpiar flows...")
            return True  # Continuar sin limpiar
            
    except Exception as e:
        logger.error(f"✗ Error limpiando flows: {e}")
        logger.warning("⚠ Continuando sin limpiar flows...")
        return True  # Continuar sin limpiar

def instalar_flows_icmp_bidireccional(mac_origen, mac_destino):
    """
    Instala flows bidireccionales para comunicación ICMP (ping)
    """
    # Verificar controlador primero
    if not verificar_controlador():
        logger.error("✗ No se pueden instalar flows ICMP: controlador no disponible")
        return False

    logger.info(f"🔄 Instalando flows ICMP bidireccionales entre {mac_origen} y {mac_destino}")
    
    src_dpid, src_port = get_attachment_points(mac_origen)
    dst_dpid, dst_port = get_attachment_points(mac_destino)

    if not src_dpid or not dst_dpid:
        logger.error("✗ No se pudo obtener los DPIDs para la ruta ICMP")
        return False

    try:
        # ============ FLOWS ICMP DE IDA (h1 → h3) ============
        logger.info("📤 Instalando flows ICMP de IDA (h1 → h3)")
        
        # Obtener ruta de ida
        url_ruta_ida = f"{FLOODLIGHT_URL}/wm/topology/route/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json"
        r_ida = requests.get(url_ruta_ida, timeout=10)
        if r_ida.status_code != 200:
            logger.error(f"✗ No se pudo obtener la ruta ICMP de ida: {r_ida.status_code}")
            return False

        ruta_ida = r_ida.json()
        for i, paso in enumerate(ruta_ida):
            dpid = paso["switch"]
            out_port = paso["port"]["portNumber"]

            # Flow de ida: ICMP requests (h1 → h3)
            flow_icmp_ida = {
                "switch": dpid,
                "name": f"flow_icmp_ida_{dpid[-4:]}_{i}",
                "priority": 1000,
                "eth_type": 2048,        # IPv4
                "ip_proto": "1",         # ICMP
                "eth_src": mac_origen,   # MAC origen (h1)
                "eth_dst": mac_destino,  # MAC destino (h3)
                "active": "true",
                "hard_timeout": 0,
                "idle_timeout": 300,     # 5 minutos de timeout
                "actions": f"output={out_port}"
            }

            logger.info(f"  📥 Instalando flow ICMP IDA en {dpid} → puerto {out_port}")
            resp = requests.post(f"{FLOODLIGHT_URL}/wm/staticflowpusher/json", json=flow_icmp_ida, timeout=10)
            if resp.status_code == 200:
                logger.info(f"  ✓ Flow ICMP IDA instalado correctamente en {dpid}")
            else:
                logger.error(f"  ✗ Error al instalar flow ICMP IDA en {dpid}: {resp.text}")
                return False
            time.sleep(0.1)

        # ============ FLOWS ICMP DE VUELTA (h3 → h1) ============
        logger.info("📨 Instalando flows ICMP de VUELTA (h3 → h1)")
        
        # Obtener ruta de vuelta (invertida)
        url_ruta_vuelta = f"{FLOODLIGHT_URL}/wm/topology/route/{dst_dpid}/{dst_port}/{src_dpid}/{src_port}/json"
        r_vuelta = requests.get(url_ruta_vuelta, timeout=10)
        if r_vuelta.status_code != 200:
            logger.error(f"✗ No se pudo obtener la ruta ICMP de vuelta: {r_vuelta.status_code}")
            return False

        ruta_vuelta = r_vuelta.json()
        for i, paso in enumerate(ruta_vuelta):
            dpid = paso["switch"]
            out_port = paso["port"]["portNumber"]

            # Flow de vuelta: ICMP replies (h3 → h1)
            flow_icmp_vuelta = {
                "switch": dpid,
                "name": f"flow_icmp_vuelta_{dpid[-4:]}_{i}",
                "priority": 1000,
                "eth_type": 2048,        # IPv4
                "ip_proto": "1",         # ICMP
                "eth_src": mac_destino,  # MAC origen (h3)
                "eth_dst": mac_origen,   # MAC destino (h1)
                "active": "true",
                "hard_timeout": 0,
                "idle_timeout": 300,     # 5 minutos de timeout
                "actions": f"output={out_port}"
            }

            logger.info(f"  📤 Instalando flow ICMP VUELTA en {dpid} → puerto {out_port}")
            resp = requests.post(f"{FLOODLIGHT_URL}/wm/staticflowpusher/json", json=flow_icmp_vuelta, timeout=10)
            if resp.status_code == 200:
                logger.info(f"  ✓ Flow ICMP VUELTA instalado correctamente en {dpid}")
            else:
                logger.error(f"  ✗ Error al instalar flow ICMP VUELTA en {dpid}: {resp.text}")
                return False
            time.sleep(0.1)

        logger.info(f"🎉 Flows ICMP bidireccionales instalados exitosamente para {mac_origen} ↔ {mac_destino}")
        return True

    except ConnectionError:
        logger.error("✗ Error de conexión al instalar flows ICMP")
        return False
    except Timeout:
        logger.error("✗ Timeout al instalar flows ICMP")
        return False
    except Exception as e:
        logger.error(f"✗ Error inesperado al instalar flows ICMP: {e}")
        return False

def instalar_flows_http_bidireccional(mac_origen, mac_destino):
    """
    Instala flows bidireccionales para comunicación HTTP en puerto 5000
    """
    # Verificar controlador primero
    if not verificar_controlador():
        logger.error("✗ No se pueden instalar flows: controlador no disponible")
        return False

    logger.info(f"🔄 Instalando flows HTTP bidireccionales entre {mac_origen} y {mac_destino}")
    
    src_dpid, src_port = get_attachment_points(mac_origen)
    dst_dpid, dst_port = get_attachment_points(mac_destino)

    if not src_dpid or not dst_dpid:
        logger.error("✗ No se pudo obtener los DPIDs para la ruta HTTP")
        return False

    try:
        # ============ FLOWS DE IDA (Cliente → Servidor) ============
        logger.info("📤 Instalando flows HTTP de IDA (cliente → servidor)")
        
        # Obtener ruta de ida
        url_ruta_ida = f"{FLOODLIGHT_URL}/wm/topology/route/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json"
        r_ida = requests.get(url_ruta_ida, timeout=10)
        if r_ida.status_code != 200:
            logger.error(f"✗ No se pudo obtener la ruta HTTP de ida: {r_ida.status_code}")
            return False

        ruta_ida = r_ida.json()
        for i, paso in enumerate(ruta_ida):
            dpid = paso["switch"]
            out_port = paso["port"]["portNumber"]

            # Flow de ida: tráfico hacia el servidor portal
            flow_ida = {
                "switch": dpid,
                "name": f"flow_http5000_ida_{dpid[-4:]}_{i}",
                "priority": 1000,
                "eth_type": 2048,        # IPv4
                "ip_proto": "6",         # TCP
                "eth_src": mac_origen,   # MAC origen
                "ipv4_dst": PORTAL_IP,   # IP destino
                "tcp_dst": str(PORTAL_TCP_PORT),  # Puerto destino
                "active": "true",
                "hard_timeout": 0,
                "idle_timeout": 300,     # 5 minutos de timeout
                "actions": f"output={out_port}"
            }

            logger.info(f"  📥 Instalando flow HTTP IDA en {dpid} → puerto {out_port}")
            resp = requests.post(f"{FLOODLIGHT_URL}/wm/staticflowpusher/json", json=flow_ida, timeout=10)
            if resp.status_code == 200:
                logger.info(f"  ✓ Flow HTTP IDA instalado correctamente en {dpid}")
            else:
                logger.error(f"  ✗ Error al instalar flow HTTP IDA en {dpid}: {resp.text}")
                return False
            time.sleep(0.1)

        # ============ FLOWS DE VUELTA (Servidor → Cliente) ============
        logger.info("📨 Instalando flows HTTP de VUELTA (servidor → cliente)")
        
        # Obtener ruta de vuelta (invertida)
        url_ruta_vuelta = f"{FLOODLIGHT_URL}/wm/topology/route/{dst_dpid}/{dst_port}/{src_dpid}/{src_port}/json"
        r_vuelta = requests.get(url_ruta_vuelta, timeout=10)
        if r_vuelta.status_code != 200:
            logger.error(f"✗ No se pudo obtener la ruta HTTP de vuelta: {r_vuelta.status_code}")
            return False

        ruta_vuelta = r_vuelta.json()
        for i, paso in enumerate(ruta_vuelta):
            dpid = paso["switch"]
            out_port = paso["port"]["portNumber"]

            # Flow de vuelta: respuestas del servidor hacia el cliente
            flow_vuelta = {
                "switch": dpid,
                "name": f"flow_http5000_vuelta_{dpid[-4:]}_{i}",
                "priority": 1000,
                "eth_type": 2048,        # IPv4
                "ip_proto": "6",         # TCP
                "eth_dst": mac_origen,   # MAC destino (cliente original)
                "ipv4_src": PORTAL_IP,   # IP origen (servidor)
                "tcp_src": str(PORTAL_TCP_PORT),  # Puerto origen
                "active": "true",
                "hard_timeout": 0,
                "idle_timeout": 300,     # 5 minutos de timeout
                "actions": f"output={out_port}"
            }

            logger.info(f"  📤 Instalando flow HTTP VUELTA en {dpid} → puerto {out_port}")
            resp = requests.post(f"{FLOODLIGHT_URL}/wm/staticflowpusher/json", json=flow_vuelta, timeout=10)
            if resp.status_code == 200:
                logger.info(f"  ✓ Flow HTTP VUELTA instalado correctamente en {dpid}")
            else:
                logger.error(f"  ✗ Error al instalar flow HTTP VUELTA en {dpid}: {resp.text}")
                return False
            time.sleep(0.1)

        logger.info(f"🎉 Flows HTTP bidireccionales instalados exitosamente para {mac_origen} ↔ {mac_destino}")
        return True

    except ConnectionError:
        logger.error("✗ Error de conexión al instalar flows HTTP")
        return False
    except Timeout:
        logger.error("✗ Timeout al instalar flows HTTP")
        return False
    except Exception as e:
        logger.error(f"✗ Error inesperado al instalar flows HTTP: {e}")
        return False
    

def instalar_flows_arp_bidireccionales(mac_origen, mac_destino):
    """
    Instala flujos bidireccionales para resolución de ARP
    """
    # Verificar controlador primero
    if not verificar_controlador():
        logger.error("✗ No se pueden instalar flujos ARP: controlador no disponible")
        return False

    logger.info(f"🔄 Instalando flujos ARP bidireccionales entre {mac_origen} y {mac_destino}")
    
    src_dpid, src_port = get_attachment_points(mac_origen)
    dst_dpid, dst_port = get_attachment_points(mac_destino)

    if not src_dpid or not dst_dpid:
        logger.error("✗ No se pudo obtener los DPIDs para la ruta ARP")
        return False

    try:
        # ============ FLOWS ARP DE IDA (h1 → h3) ============

        logger.info("📤 Instalando flujos ARP de IDA (h1 → h3)")
        
        # Obtener ruta de ida
        url_ruta_ida = f"{FLOODLIGHT_URL}/wm/topology/route/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json"
        r_ida = requests.get(url_ruta_ida, timeout=10)
        if r_ida.status_code != 200:
            logger.error(f"✗ No se pudo obtener la ruta ARP de ida: {r_ida.status_code}")
            return False

        ruta_ida = r_ida.json()
        for i, paso in enumerate(ruta_ida):
            dpid = paso["switch"]
            out_port = paso["port"]["portNumber"]

            # Flow de ida: ARP requests (h1 → h3)
            flow_arp_ida = {
                "switch": dpid,
                "name": f"flow_arp_ida_{dpid[-4:]}_{i}",
                "priority": 1000,
                "eth_type": 2054,        # ARP
                "eth_src": mac_origen,   # MAC origen (h1)
                "eth_dst": mac_destino,  # MAC destino (h3)
                "active": "true",
                "hard_timeout": 0,
                "idle_timeout": 300,     # 5 minutos de timeout
                "actions": f"output={out_port}"
            }

            logger.info(f"  📥 Instalando flow ARP IDA en {dpid} → puerto {out_port}")
            resp = requests.post(f"{FLOODLIGHT_URL}/wm/staticflowpusher/json", json=flow_arp_ida, timeout=10)
            if resp.status_code == 200:
                logger.info(f"  ✓ Flow ARP IDA instalado correctamente en {dpid}")
            else:
                logger.error(f"  ✗ Error al instalar flow ARP IDA en {dpid}: {resp.text}")
                return False
            time.sleep(0.1)

        # ============ FLOWS ARP DE VUELTA (h3 → h1) ============

        logger.info("📨 Instalando flujos ARP de VUELTA (h3 → h1)")
        
        # Obtener ruta de vuelta (invertida)
        url_ruta_vuelta = f"{FLOODLIGHT_URL}/wm/topology/route/{dst_dpid}/{dst_port}/{src_dpid}/{src_port}/json"
        r_vuelta = requests.get(url_ruta_vuelta, timeout=10)
        if r_vuelta.status_code != 200:
            logger.error(f"✗ No se pudo obtener la ruta ARP de vuelta: {r_vuelta.status_code}")
            return False

        ruta_vuelta = r_vuelta.json()
        for i, paso in enumerate(ruta_vuelta):
            dpid = paso["switch"]
            out_port = paso["port"]["portNumber"]

            # Flow de vuelta: ARP replies (h3 → h1)
            flow_arp_vuelta = {
                "switch": dpid,
                "name": f"flow_arp_vuelta_{dpid[-4:]}_{i}",
                "priority": 1000,
                "eth_type": 2054,        # ARP
                "eth_src": mac_destino,  # MAC origen (h3)
                "eth_dst": mac_origen,   # MAC destino (h1)
                "active": "true",
                "hard_timeout": 0,
                "idle_timeout": 300,     # 5 minutos de timeout
                "actions": f"output={out_port}"
            }

            logger.info(f"  📤 Instalando flow ARP VUELTA en {dpid} → puerto {out_port}")
            resp = requests.post(f"{FLOODLIGHT_URL}/wm/staticflowpusher/json", json=flow_arp_vuelta, timeout=10)
            if resp.status_code == 200:
                logger.info(f"  ✓ Flow ARP VUELTA instalado correctamente en {dpid}")
            else:
                logger.error(f"  ✗ Error al instalar flow ARP VUELTA en {dpid}: {resp.text}")
                return False
            time.sleep(0.1)

        logger.info(f"🎉 Flujos ARP bidireccionales instalados exitosamente para {mac_origen} ↔ {mac_destino}")
        return True

    except ConnectionError:
        logger.error("✗ Error de conexión al instalar flujos ARP")
        return False
    except Timeout:
        logger.error("✗ Timeout al instalar flujos ARP")
        return False
    except Exception as e:
        logger.error(f"✗ Error inesperado al instalar flujos ARP: {e}")
        return False


def instalar_flows_completos(mac_origen, mac_destino):
    """
    Instala flows completos: HTTP + ICMP (ping) bidireccionales
    """
    logger.info(f"🚀 Instalando flows completos (HTTP + ICMP) entre {mac_origen} y {mac_destino}")
    
    # Intentar limpiar flows existentes (no crítico si falla)
    limpiar_flows_existentes()
    
    # Instalar flows ARP
    resultado_arp = instalar_flows_arp_bidireccionales(mac_origen, mac_destino)
    if not resultado_arp:
        logger.error("✗ Error al instalar flows ICMP")
        return False

    # Instalar flows HTTP
    resultado_http = instalar_flows_http_bidireccional(mac_origen, mac_destino)
    if not resultado_http:
        logger.error("✗ Error al instalar flows HTTP")
        return False
    
    # Instalar flows ICMP
    resultado_icmp = instalar_flows_icmp_bidireccional(mac_origen, mac_destino)
    if not resultado_icmp:
        logger.error("✗ Error al instalar flows ICMP")
        return False
    
    logger.info("🎉 Flows completos (HTTP + ICMP) instalados exitosamente")
    return True

# Endpoint para instalar flows HTTP manualmente
@app.route("/flows/install", methods=["POST"])
def instalar_flows_endpoint():
    """
    Endpoint para instalar flows HTTP manualmente
    POST /flows/install
    {
        "mac_origen": "fa:16:3e:55:70:7a",
        "mac_destino": "fa:16:3e:e6:f6:7a"
    }
    """
    try:
        data = request.json
        mac_origen = data.get("mac_origen")
        mac_destino = data.get("mac_destino")
        
        if not mac_origen or not mac_destino:
            return jsonify({"error": "mac_origen y mac_destino son requeridos"}), 400
        
        resultado = instalar_flows_http_bidireccional(mac_origen, mac_destino)
        
        if resultado:
            return jsonify({
                "status": "success",
                "message": "Flows HTTP instalados correctamente",
                "mac_origen": mac_origen,
                "mac_destino": mac_destino
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Error al instalar flows HTTP"
            }), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint para instalar flows ICMP manualmente
@app.route("/flows/install-icmp", methods=["POST"])
def instalar_flows_icmp_endpoint():
    """
    Endpoint para instalar flows ICMP (ping) manualmente
    POST /flows/install-icmp
    {
        "mac_origen": "fa:16:3e:55:70:7a",
        "mac_destino": "fa:16:3e:e6:f6:7a"
    }
    """
    try:
        data = request.json
        mac_origen = data.get("mac_origen")
        mac_destino = data.get("mac_destino")
        
        if not mac_origen or not mac_destino:
            return jsonify({"error": "mac_origen y mac_destino son requeridos"}), 400
        
        resultado = instalar_flows_icmp_bidireccional(mac_origen, mac_destino)
        
        if resultado:
            return jsonify({
                "status": "success",
                "message": "Flows ICMP instalados correctamente",
                "mac_origen": mac_origen,
                "mac_destino": mac_destino
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Error al instalar flows ICMP"
            }), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint para instalar flows completos (HTTP + ICMP)
@app.route("/flows/install-complete", methods=["POST"])
def instalar_flows_completos_endpoint():
    """
    Endpoint para instalar flows completos (HTTP + ICMP)
    POST /flows/install-complete
    {
        "mac_origen": "fa:16:3e:55:70:7a",
        "mac_destino": "fa:16:3e:e6:f6:7a"
    }
    """
    try:
        data = request.json
        mac_origen = data.get("mac_origen")
        mac_destino = data.get("mac_destino")
        
        if not mac_origen or not mac_destino:
            return jsonify({"error": "mac_origen y mac_destino son requeridos"}), 400
        
        resultado = instalar_flows_completos(mac_origen, mac_destino)
        
        if resultado:
            return jsonify({
                "status": "success",
                "message": "Flows completos (HTTP + ICMP) instalados correctamente",
                "mac_origen": mac_origen,
                "mac_destino": mac_destino
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Error al instalar flows completos"
            }), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Endpoint para verificar estado del controlador
@app.route("/controller/status", methods=["GET"])
def controller_status():
    """
    Endpoint para verificar el estado del controlador
    """
    disponible = verificar_controlador()
    return jsonify({
        "controller_url": FLOODLIGHT_URL,
        "disponible": disponible,
        "timestamp": time.time()
    })

# EMPIEZA CRUDS

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
    puerto = data.get("puerto")
    id_rol = data.get("idRol")
    if not nombre or not ip or not id_rol:
        return jsonify({"error": "nombre, ip, puerto e idRol son requeridos"}), 400
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO servicios (nombre, ip, puerto, idRol) VALUES (%s, %s, %s, %s)", (nombre, ip, puerto, id_rol))
    conn.commit()
    conn.close()
    return jsonify({"status": "created", "nombre": nombre, "ip": ip, "puerto":puerto, "idRol": id_rol}), 201

@app.route("/servicios/<int:id>", methods=["PUT"])
def actualizar_servicio(id):
    data = request.json
    nombre = data.get("nombre")
    ip = data.get("ip")
    puerto = data.get("puerto")
    id_rol = data.get("idRol")
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE servicios SET nombre = %s, ip = %s, puerto = %s, idRol = %s WHERE id = %s
        """, (nombre, ip, puerto, id_rol, id))
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
    logger.info("🚀 Iniciando API...")
    
    # Verificar controlador al inicio (sin fallar si no está)
    if verificar_controlador():
        logger.info("🎯 Intentando instalar flows de prueba...")
        # Instalar flows completos (HTTP + ICMP) de prueba
        resultado = instalar_flows_completos("fa:16:3e:55:70:7a", "fa:16:3e:e6:f6:7a")
        if resultado:
            logger.info("✅ Flows completos (HTTP + ICMP) instalados correctamente")
        else:
            logger.warning("⚠ No se pudieron instalar flows completos")
    else:
        logger.warning("⚠ Controlador no disponible al inicio - La API funcionará sin flows")
    
    logger.info("🌐 Iniciando servidor Flask en puerto 5010...")
    app.run(host="0.0.0.0", port=5010)
