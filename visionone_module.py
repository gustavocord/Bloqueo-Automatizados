# visionone_module.py

import os
import requests
import logging
from typing import List

# --- Configuración desde .env ---
TMVO_API_KEY  = os.getenv("TMVO_API_KEY")
TMVO_ENDPOINT = os.getenv("TMVO_ENDPOINT", "https://api.xdr.trendmicro.com")

# Logger del módulo
logger = logging.getLogger(__name__)

def bloqueo_IP(ips: List[str]) -> None:
    """
    Envía una lista de IPs a Vision One usando el payload
    que ya probaste ('ip' + 'description').
    """
    url = f"{TMVO_ENDPOINT}/v3.0/response/suspiciousObjects"
    headers = {
        "Authorization": f"Bearer {TMVO_API_KEY}",
        "Content-Type": "application/json"
    }

    # Construimos el body tal como lo probaste, uno por IP
    body = [
        {
            "description": "BLOQUEO AUTOMATICO - CLOUDFLARE",
            "ip": ip
        }
        for ip in ips
    ]

    logger.info("Enviando %d IPs a Vision One vía bloqueo_IP(): %s", len(ips), ips)
    resp = requests.post(url, headers=headers, json=body, timeout=30)

    logger.info("Vision One RESP STATUS: %s", resp.status_code)
    try:
        logger.debug("Vision One RESP BODY: %s", resp.json())
    except ValueError:
        logger.warning("Vision One devolvió body no JSON: %s", resp.text)

    # Esto levantará excepción si no es un 2xx o 207
    resp.raise_for_status()
