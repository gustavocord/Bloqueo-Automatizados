from dotenv import load_dotenv
load_dotenv()
import logging
import os
import cloudflare_module as cf
import visionone_module as v1

# Configuración de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Ruta donde guardaremos el histórico de IPs bloqueadas
BLOCKED_IPS_FILE = os.path.join(os.path.dirname(__file__), "blocked_ips.txt")

def run():
    logging.info("=== Inicio del workflow CF ➜ VT ➜ Vision One ===")

    # 1) Recopilar y bloquear en CF las IPs maliciosas
    ips_maliciosas = cf.collect_ips()
    logging.info("Maliciosas encontradas: %s", ips_maliciosas)

    # 2) Enviar a Vision One (Suspicious Object List)
    v1.bloqueo_IP(ips_maliciosas)
    logging.info("Proceso completado ✔")

    # 3) Registrar en txt solo las IPs nuevas
    existentes = set()
    if os.path.isfile(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            existentes = {ip.strip() for ip in f if ip.strip()}

    nuevas = set(ips_maliciosas) - existentes
    if nuevas:
        with open(BLOCKED_IPS_FILE, "a") as f:
            for ip in sorted(nuevas):
                f.write(ip + "\n")
        logging.info("Registradas %d IPs nuevas en %s", len(nuevas), BLOCKED_IPS_FILE)
    else:
        logging.info("No hubo IPs nuevas para registrar")

if __name__ == "__main__":
    run()
