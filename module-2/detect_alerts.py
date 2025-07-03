import json

EVE_FILE = "logs/eve.json"

def monitor_eve_log():
    print("📡 Escuchando eventos de Suricata en tiempo real...\n")
    with open(EVE_FILE, "r") as file:
        # Saltamos al final del archivo
        file.seek(0, 2)

        while True:
            line = file.readline()
            if not line:
                continue  # no hay línea nueva, espera...
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    print("🚨 Alerta detectada:")
                    print(f"  ➤ IP origen: {event.get('src_ip')}")
                    print(f"  ➤ IP destino: {event.get('dest_ip')}")
                    print(f"  ➤ Descripción: {event['alert']['signature']}")
                    print("-" * 40)
            except json.JSONDecodeError:
                continue  # línea corrupta o incompleta

if __name__ == "__main__":
    monitor_eve_log()
